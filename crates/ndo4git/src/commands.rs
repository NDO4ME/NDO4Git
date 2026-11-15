//! Command implementations.

use crate::cli::{Cli, Command, HostAction, Shell};
use crate::{prompt, render};
use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Table};
use ndo4git_core::crypto::{record_aad, MasterKey};
use ndo4git_core::db::{Db, KeyRow, NewKey};
use ndo4git_core::exec::HostKeyPolicy;
use ndo4git_core::forge::Forge;
use ndo4git_core::install::{write_atomic, Plan};
use ndo4git_core::manifest::{Manifest, MANIFEST_FILE};
use ndo4git_core::plan as reconcile;
use ndo4git_core::repo::{normalize_host, parse_remote_url, parse_target, DEFAULT_HOST};
use ndo4git_core::util::{fmt_ts, hostname, now_unix};
use ndo4git_core::{backup, keygen, paths};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

/// Exit code when `new` finds an existing key and `--rotate` was not given.
const EXIT_EXISTS: u8 = 2;

/// Exit code of `plan --check` when the manifest and reality differ.
const EXIT_DRIFT: u8 = 2;

pub fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let sudo = cli.sudo_user_home;
    let host_flag = cli.host.as_deref();
    match cli.command {
        Command::New {
            target,
            rotate,
            comment,
            json,
        } => cmd_new(
            sudo,
            host_flag,
            target.as_deref(),
            rotate,
            comment.as_deref(),
            json,
        ),
        Command::SshWrapper { args } => {
            // Normally intercepted in main(); reachable via `git ndo4git ssh-wrapper`.
            let code = ndo4git_core::exec::run_wrapper(args.into_iter().map(Into::into).collect());
            Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
        }
        Command::List { json } => cmd_list(sudo, json),
        Command::Show { repo, json } => cmd_show(sudo, host_flag, &repo, json),
        Command::Rm { repo } => cmd_rm(sudo, host_flag, &repo),
        Command::Import {
            repo,
            file,
            force,
            comment,
        } => cmd_import(sudo, host_flag, &repo, &file, force, comment.as_deref()),
        Command::ExportPub { repo } => cmd_export_pub(sudo, host_flag, &repo),
        Command::ExportPrivate { repo, yes } => cmd_export_private(sudo, host_flag, &repo, yes),
        Command::Alias { old, new, remove } => cmd_alias(sudo, host_flag, &old, &new, remove),
        Command::Host { action } => cmd_host(sudo, action),
        Command::Backup {
            file,
            force,
            passphrase_file,
        } => cmd_backup(sudo, &file, force, passphrase_file.as_deref()),
        Command::Restore {
            file,
            overwrite,
            passphrase_file,
        } => cmd_restore(sudo, &file, overwrite, passphrase_file.as_deref()),
        Command::Init { force } => cmd_init(sudo, cli.manifest.as_deref(), force),
        Command::Plan { check, json } => cmd_plan(sudo, cli.manifest.as_deref(), check, json),
        Command::Apply { json } => cmd_apply(sudo, cli.manifest.as_deref(), json),
        Command::Rollback { json } => cmd_rollback(sudo, json),
        Command::Whoami { target, json } => cmd_whoami(
            sudo,
            cli.manifest.as_deref(),
            host_flag,
            target.as_deref(),
            json,
        ),
        Command::Schema => cmd_schema(),
        Command::Install => {
            for l in Plan::system()?.install()? {
                println!("{l}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Uninstall { purge } => {
            for l in Plan::system()?.uninstall(purge)? {
                println!("{l}");
            }
            Ok(ExitCode::SUCCESS)
        }
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let sh = match shell {
                Shell::Bash => clap_complete::Shell::Bash,
                Shell::Zsh => clap_complete::Shell::Zsh,
                Shell::Fish => clap_complete::Shell::Fish,
                Shell::Elvish => clap_complete::Shell::Elvish,
            };
            clap_complete::generate(sh, &mut cmd, "ndo4git", &mut std::io::stdout());
            Ok(ExitCode::SUCCESS)
        }
        Command::Man => {
            clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout())?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

// ------------------------------------------------------------------ helpers

fn open_db(sudo: bool) -> Result<(PathBuf, Db)> {
    let dir = paths::config_dir(sudo)?;
    paths::ensure_dir(&dir)?;
    let db = Db::open_and_migrate(&paths::db_path(&dir))?;
    Ok((dir, db))
}

/// Resolve `(host, repo)` from a user argument: a URL's host wins, then `--host`, then github.com.
fn resolve(host_flag: Option<&str>, arg: &str) -> Result<(String, String)> {
    let (url_host, repo) = parse_target(arg)?;
    let host = match (url_host, host_flag) {
        (Some(h), _) => h,
        (None, Some(h)) => normalize_host(h)?,
        (None, None) => DEFAULT_HOST.to_owned(),
    };
    Ok((host, repo))
}

fn origin_remote() -> Result<(String, String)> {
    let out = std::process::Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .context("running `git remote get-url origin`")?;
    if !out.status.success() {
        bail!(
            "no repository given and `git remote get-url origin` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let url = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let r = parse_remote_url(&url).with_context(|| format!("cannot parse origin URL {url:?}"))?;
    Ok((r.host, r.repo))
}

fn require_key(db: &Db, host: &str, repo: &str) -> Result<KeyRow> {
    db.get_key(repo, host)?
        .ok_or_else(|| anyhow::anyhow!("no key for {repo} on {host}"))
}

fn warn_if_unmanaged_host(db: &Db, host: &str) -> Result<()> {
    if !db.hosts()?.iter().any(|h| h == host) {
        eprintln!(
            "ndo4git: warning: {host} is not a managed host, so git will not use this key until you run: ndo4git host add {host}"
        );
    }
    Ok(())
}

/// Encrypt `pem` for `(repo, host)` and store it.
struct Stored {
    enc: Vec<u8>,
    nonce: [u8; ndo4git_core::crypto::NONCE_LEN],
}

fn seal_key(master: &MasterKey, repo: &str, host: &str, k: &keygen::KeyMaterial) -> Result<Stored> {
    let aad = record_aad(repo, host, &k.algo);
    let (enc, nonce) = master.seal(&aad, k.private_openssh.as_bytes())?;
    Ok(Stored { enc, nonce })
}

fn save(
    db: &mut Db,
    repo: &str,
    host: &str,
    k: &keygen::KeyMaterial,
    st: &Stored,
    replace_reason: Option<&str>,
) -> Result<()> {
    let nk = NewKey {
        repo,
        host,
        algo: &k.algo,
        public_key: &k.public_openssh,
        private_key_enc: &st.enc,
        nonce: &st.nonce,
        fingerprint: &k.fingerprint,
        can_write: false,
        created_at: now_unix(),
        last_used_at: None,
    };
    match replace_reason {
        Some(r) => db.replace_key(&nk, now_unix(), r)?,
        None => db.insert_key(&nk)?,
    };
    Ok(())
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn ts(t: Option<i64>) -> String {
    t.map_or_else(|| "-".to_owned(), fmt_ts)
}

// ------------------------------------------------------------------ commands

#[allow(clippy::fn_params_excessive_bools)]
fn cmd_new(
    sudo: bool,
    host_flag: Option<&str>,
    target: Option<&str>,
    rotate: bool,
    comment: Option<&str>,
    json: bool,
) -> Result<ExitCode> {
    let (host, repo) = match target {
        Some(t) => resolve(host_flag, t)?,
        None => origin_remote()?,
    };
    let (dir, mut db) = open_db(sudo)?;
    let existing = db.get_key(&repo, &host)?;
    if let (Some(k), false) = (&existing, rotate) {
        if json {
            print_json(&render::new_json(k, db.forge(&host)?, false))?;
        } else {
            print!("{}", render::new_block(k, db.forge(&host)?));
        }
        eprintln!("ndo4git: a key for {repo} on {host} already exists; use --rotate to replace it");
        return Ok(ExitCode::from(EXIT_EXISTS));
    }
    let comment = comment.map_or_else(
        || keygen::default_comment(&repo, &hostname()),
        str::to_owned,
    );
    let material = keygen::generate(&comment)?;
    let master = MasterKey::load_or_create(&dir)?;
    let stored = seal_key(&master, &repo, &host, &material)?;
    save(
        &mut db,
        &repo,
        &host,
        &material,
        &stored,
        existing.as_ref().map(|_| "rotate"),
    )?;
    warn_if_unmanaged_host(&db, &host)?;
    let row = require_key(&db, &host, &repo)?;
    if json {
        print_json(&render::new_json(&row, db.forge(&host)?, true))?;
    } else {
        print!("{}", render::new_block(&row, db.forge(&host)?));
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_list(sudo: bool, json: bool) -> Result<ExitCode> {
    let (_, db) = open_db(sudo)?;
    let keys = db.list_keys()?;
    if json {
        print_json(&keys)?;
        return Ok(ExitCode::SUCCESS);
    }
    let mut t = Table::new();
    t.load_preset(UTF8_FULL_CONDENSED);
    t.set_header(["REPO", "HOST", "FINGERPRINT", "CREATED", "LAST USED"]);
    for k in &keys {
        t.add_row([
            k.repo.clone(),
            k.host.clone(),
            k.fingerprint.clone(),
            fmt_ts(k.created_at),
            ts(k.last_used_at),
        ]);
    }
    println!("{t}");
    Ok(ExitCode::SUCCESS)
}

fn cmd_show(sudo: bool, host_flag: Option<&str>, repo: &str, json: bool) -> Result<ExitCode> {
    let (host, repo) = resolve(host_flag, repo)?;
    let (_, db) = open_db(sudo)?;
    let k = require_key(&db, &host, &repo)?;
    let history = db.history(k.id)?;
    let aliases: Vec<_> = db
        .list_aliases()?
        .into_iter()
        .filter(|a| a.target == repo && a.host == host)
        .collect();
    if json {
        #[derive(serde::Serialize)]
        struct Out<'a> {
            key: &'a KeyRow,
            history: &'a [ndo4git_core::db::HistoryRow],
            aliases: Vec<&'a str>,
        }
        print_json(&Out {
            key: &k,
            history: &history,
            aliases: aliases.iter().map(|a| a.alias.as_str()).collect(),
        })?;
        return Ok(ExitCode::SUCCESS);
    }
    println!("Repo:         {}", k.repo);
    println!("Host:         {}", k.host);
    println!("Algorithm:    {}", k.algo);
    println!("Fingerprint:  {}", k.fingerprint);
    println!("Created:      {}", fmt_ts(k.created_at));
    println!("Rotated:      {}", ts(k.rotated_at));
    println!("Last used:    {}", ts(k.last_used_at));
    println!("Public key:   {}", k.public_key);
    if !aliases.is_empty() {
        println!(
            "Aliases:      {}",
            aliases
                .iter()
                .map(|a| a.alias.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for h in &history {
        println!(
            "Previous:     {} (retired {}, {})",
            h.fingerprint,
            fmt_ts(h.retired_at),
            h.reason
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_rm(sudo: bool, host_flag: Option<&str>, repo: &str) -> Result<ExitCode> {
    let (host, repo) = resolve(host_flag, repo)?;
    let (_, mut db) = open_db(sudo)?;
    if !db.delete_key(&repo, &host)? {
        bail!("no key for {repo} on {host}");
    }
    eprintln!("removed key for {repo} on {host} (remember to delete the public key on {host})");
    Ok(ExitCode::SUCCESS)
}

fn cmd_import(
    sudo: bool,
    host_flag: Option<&str>,
    repo: &str,
    file: &Path,
    force: bool,
    comment: Option<&str>,
) -> Result<ExitCode> {
    let (host, repo) = resolve(host_flag, repo)?;
    let pem = Zeroizing::new(if file == Path::new("-") {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("reading stdin")?;
        s
    } else {
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?
    });
    let comment = comment.map_or_else(
        || keygen::default_comment(&repo, &hostname()),
        str::to_owned,
    );
    let material = keygen::from_private_openssh(&pem, Some(&comment))?;
    let (dir, mut db) = open_db(sudo)?;
    let exists = db.get_key(&repo, &host)?.is_some();
    if exists && !force {
        bail!("a key for {repo} on {host} already exists; use --force to replace it");
    }
    let master = MasterKey::load_or_create(&dir)?;
    let stored = seal_key(&master, &repo, &host, &material)?;
    save(
        &mut db,
        &repo,
        &host,
        &material,
        &stored,
        exists.then_some("import"),
    )?;
    warn_if_unmanaged_host(&db, &host)?;
    print!(
        "{}",
        render::new_block(&require_key(&db, &host, &repo)?, db.forge(&host)?)
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_export_pub(sudo: bool, host_flag: Option<&str>, repo: &str) -> Result<ExitCode> {
    let (host, repo) = resolve(host_flag, repo)?;
    let (_, db) = open_db(sudo)?;
    println!("{}", require_key(&db, &host, &repo)?.public_key);
    Ok(ExitCode::SUCCESS)
}

fn cmd_export_private(
    sudo: bool,
    host_flag: Option<&str>,
    repo: &str,
    yes: bool,
) -> Result<ExitCode> {
    if !yes {
        bail!("refusing to print a private key without --yes");
    }
    let (host, repo) = resolve(host_flag, repo)?;
    let (dir, db) = open_db(sudo)?;
    let s = db
        .resolve_secret(&repo, &host)?
        .ok_or_else(|| anyhow::anyhow!("no key for {repo} on {host}"))?;
    let master = MasterKey::load(&dir)?;
    let pem = master.open(
        &record_aad(&s.row.repo, &s.row.host, &s.row.algo),
        &s.nonce,
        &s.private_key_enc,
    )?;
    let mut out = std::io::stdout().lock();
    out.write_all(&pem)?;
    out.flush()?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_alias(
    sudo: bool,
    host_flag: Option<&str>,
    old: &str,
    new: &str,
    remove: bool,
) -> Result<ExitCode> {
    let (host, old) = resolve(host_flag, old)?;
    let (_, mut db) = open_db(sudo)?;
    if remove {
        if !db.remove_alias(&old, &host)? {
            bail!("no alias {old} on {host}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    let (new_host, new) = resolve(Some(&host), new)?;
    if new_host != host {
        bail!("alias and target must be on the same host");
    }
    db.add_alias(&old, &new, &host, now_unix())?;
    eprintln!("{old} on {host} now uses the key of {new}");
    Ok(ExitCode::SUCCESS)
}

fn cmd_host(sudo: bool, action: HostAction) -> Result<ExitCode> {
    let (_, db) = open_db(sudo)?;
    let mut hosts = db.hosts()?;
    match action {
        HostAction::List { json } => {
            if json {
                let rows = hosts
                    .iter()
                    .map(|h| Ok(serde_json::json!({ "host": h, "forge": db.forge(h)?.name() })))
                    .collect::<Result<Vec<_>>>()?;
                return print_json(&rows).map(|()| ExitCode::SUCCESS);
            }
        }
        HostAction::Add { host, forge } => {
            let h = normalize_host(&host)?;
            if let Some(f) = forge {
                let f = Forge::parse(&f).ok_or_else(|| {
                    anyhow::anyhow!("unknown forge {f:?} (github, gitlab, forgejo)")
                })?;
                db.set_forge(&h, f)?;
            }
            if !hosts.contains(&h) {
                hosts.push(h);
                db.set_hosts(&hosts)?;
            }
        }
        HostAction::Rm { host } => {
            let h = normalize_host(&host)?;
            hosts.retain(|x| *x != h);
            db.set_hosts(&hosts)?;
        }
        HostAction::Hostkey { policy } => {
            if let Some(v) = policy {
                let p = HostKeyPolicy::parse(&v).ok_or_else(|| {
                    anyhow::anyhow!("unknown policy {v:?} (accept-new, ask, strict)")
                })?;
                db.set_hostkey_policy(p)?;
                if p == HostKeyPolicy::Strict {
                    eprintln!(
                        "strict: only hosts already in known_hosts are accepted; add one first with\n  ssh-keyscan HOST | tee /dev/stderr >> ~/.ssh/known_hosts   (then compare with the forge's published fingerprints)"
                    );
                }
            }
            println!("{}", db.hostkey_policy()?.name());
            return Ok(ExitCode::SUCCESS);
        }
    }
    for h in hosts {
        println!("{h}\t{}", db.forge(&h)?);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_backup(sudo: bool, file: &Path, force: bool, pw_file: Option<&Path>) -> Result<ExitCode> {
    if file.exists() && !force {
        bail!("{} exists; use --force to overwrite", file.display());
    }
    let (dir, db) = open_db(sudo)?;
    let master = MasterKey::load_or_create(&dir)?;
    let pw = prompt::passphrase(pw_file, true)?;
    let blob = backup::create(&db, &master, &pw)?;
    write_private_file(file, &blob)?;
    eprintln!("wrote {} ({} bytes)", file.display(), blob.len());
    Ok(ExitCode::SUCCESS)
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("ndo4git-tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn cmd_restore(
    sudo: bool,
    file: &Path,
    overwrite: bool,
    pw_file: Option<&Path>,
) -> Result<ExitCode> {
    let blob = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let (dir, mut db) = open_db(sudo)?;
    let master = MasterKey::load_or_create(&dir)?;
    let pw = prompt::passphrase(pw_file, false)?;
    let r = backup::restore(&mut db, &master, &pw, &blob, overwrite)?;
    for (label, items) in [
        ("imported", &r.imported),
        ("replaced", &r.replaced),
        ("skipped (exists)", &r.skipped),
    ] {
        for i in items {
            println!("{label}: {i}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ------------------------------------------------------------------ manifest

fn manifest_path(dir: &Path, over: Option<&Path>) -> PathBuf {
    over.map_or_else(|| dir.join(MANIFEST_FILE), Path::to_path_buf)
}

fn load_manifest(path: &Path) -> Result<Manifest> {
    let meta = std::fs::metadata(path).with_context(|| {
        format!(
            "no manifest at {} (create one with `ndo4git init`)",
            path.display()
        )
    })?;
    if meta.len() > 1 << 20 {
        bail!("{} is larger than 1 MiB", path.display());
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(Manifest::parse(&text)?)
}

fn print_actions(actions: &[reconcile::Action]) {
    for a in actions {
        println!("{} {}", a.symbol(), a.describe());
    }
}

fn cmd_init(sudo: bool, over: Option<&Path>, force: bool) -> Result<ExitCode> {
    let (dir, db) = open_db(sudo)?;
    let path = manifest_path(&dir, over);
    if path.exists() && !force {
        bail!("{} exists; use --force to overwrite", path.display());
    }
    let ctx = reconcile::Ctx {
        dir: &dir,
        git_env: &[],
    };
    let text = reconcile::init_manifest(&reconcile::gather(&ctx, &db)?)?;
    write_atomic(&path, text.as_bytes(), 0o600)?;
    eprintln!("wrote {}", path.display());
    Ok(ExitCode::SUCCESS)
}

fn cmd_plan(sudo: bool, over: Option<&Path>, check: bool, json: bool) -> Result<ExitCode> {
    let (dir, db) = open_db(sudo)?;
    let manifest = load_manifest(&manifest_path(&dir, over))?;
    let ctx = reconcile::Ctx {
        dir: &dir,
        git_env: &[],
    };
    let actions = reconcile::plan(&ctx, &db, &manifest)?;
    if json {
        print_json(&actions)?;
    } else if actions.is_empty() {
        println!("up to date: the manifest matches reality");
    } else {
        print_actions(&actions);
        println!("{} change(s) pending; run `ndo4git apply`", actions.len());
    }
    Ok(if check && !actions.is_empty() {
        ExitCode::from(EXIT_DRIFT)
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_apply(sudo: bool, over: Option<&Path>, json: bool) -> Result<ExitCode> {
    if sudo {
        bail!(
            "apply changes the invoking user's git configuration; run it without --sudo-user-home"
        );
    }
    refuse_root("apply")?;
    let (dir, mut db) = open_db(sudo)?;
    let _lock = reconcile::lock(&dir)?;
    let manifest = load_manifest(&manifest_path(&dir, over))?;
    let ctx = reconcile::Ctx {
        dir: &dir,
        git_env: &[],
    };
    if !manifest.identities.is_empty() {
        reconcile::require_hasconfig(ctx.git_env)?;
    }
    let actions = reconcile::plan(&ctx, &db, &manifest)?;
    if !json {
        if actions.is_empty() {
            println!("up to date: nothing to do");
            return Ok(ExitCode::SUCCESS);
        }
        print_actions(&actions);
    }
    reconcile::apply(&ctx, &mut db, &actions)?;
    let mut created = Vec::new();
    for a in &actions {
        if let reconcile::Action::KeyCreate { host, repo } = a {
            created.push(require_key(&db, host, repo)?);
        }
    }
    if json {
        let keys = created
            .iter()
            .map(|k| Ok(render::new_json(k, db.forge(&k.host)?, true)))
            .collect::<Result<Vec<_>>>()?;
        print_json(&serde_json::json!({ "applied": actions, "created_keys": keys }))?;
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "applied {} change(s); undo with `ndo4git rollback`",
        actions.len()
    );
    for k in &created {
        println!();
        print!("{}", render::new_block(k, db.forge(&k.host)?));
    }
    Ok(ExitCode::SUCCESS)
}

/// `apply` and `rollback` edit the invoking user's `~/.gitconfig`; as root they
/// would write root-owned files into a user's home or the wrong home.
fn refuse_root(what: &str) -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        bail!("`{what}` edits your git configuration; run it as your normal user, not root/sudo");
    }
    Ok(())
}

fn cmd_rollback(sudo: bool, json: bool) -> Result<ExitCode> {
    refuse_root("rollback")?;
    let (dir, mut db) = open_db(sudo)?;
    let _lock = reconcile::lock(&dir)?;
    let ctx = reconcile::Ctx {
        dir: &dir,
        git_env: &[],
    };
    let report = reconcile::rollback(&ctx, &mut db)?;
    for w in &report.warnings {
        eprintln!("ndo4git: {w}");
    }
    if json {
        print_json(&report)?;
        return Ok(ExitCode::SUCCESS);
    }
    for a in report.reverted.iter().rev() {
        println!("reverted {} {}", a.symbol(), a.describe());
    }
    println!("rolled back {} change(s)", report.reverted.len());
    Ok(ExitCode::SUCCESS)
}

fn git_config_value(key: &str) -> Option<String> {
    let o = std::process::Command::new("git")
        .args(["config", "--get", key])
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// One compared identity field for `whoami`.
struct Field {
    label: &'static str,
    key: &'static str,
    want: String,
    have: Option<String>,
}

fn cmd_whoami(
    sudo: bool,
    over: Option<&Path>,
    host_flag: Option<&str>,
    target: Option<&str>,
    json: bool,
) -> Result<ExitCode> {
    let (host, repo) = match target {
        Some(t) => resolve(host_flag, t)?,
        None => origin_remote()?,
    };
    let dir = paths::config_dir(sudo)?;
    let manifest = load_manifest(&manifest_path(&dir, over))?;
    let matching = manifest.identities_for(&host, &repo);
    let Some(last) = matching.last() else {
        if json {
            print_json(&serde_json::json!({
                "host": host, "repo": repo, "identity": null, "ok": true
            }))?;
        } else {
            println!("Repo:      {repo} on {host}");
            println!("Identity:  none (no manifest identity matches)");
        }
        return Ok(ExitCode::SUCCESS);
    };
    // git includes every matching identity and later ones override earlier ones per field
    let name = matching.iter().rev().find_map(|i| i.name.as_deref());
    let email = matching.iter().rev().find_map(|i| i.email.as_deref());
    let ids: Vec<&str> = matching.iter().map(|i| i.id.as_str()).collect();
    // only compare with git when inspecting the repository we are standing in
    let live = target.is_none();
    let mut fields = Vec::new();
    for (label, key, want) in [("Name", "user.name", name), ("Email", "user.email", email)] {
        if let Some(want) = want {
            fields.push(Field {
                label,
                key,
                want: want.to_owned(),
                have: if live { git_config_value(key) } else { None },
            });
        }
    }
    let ok = fields
        .iter()
        .all(|f| !live || f.have.as_deref() == Some(f.want.as_str()));
    if json {
        let detail: Vec<_> = fields
            .iter()
            .map(|f| {
                serde_json::json!({
                    "key": f.key, "expected": f.want,
                    "actual": f.have, "matches": !live || f.have.as_deref() == Some(f.want.as_str()),
                })
            })
            .collect();
        print_json(&serde_json::json!({
            "host": host, "repo": repo, "identity": last.id, "identities": ids,
            "checked_against_git": live, "fields": detail, "ok": ok
        }))?;
    } else {
        println!("Repo:      {repo} on {host}");
        println!("Identity:  {}", ids.join(" + "));
        for f in &fields {
            let note = match (&f.have, live) {
                (have, true) if have.as_deref() != Some(f.want.as_str()) => format!(
                    "   MISMATCH: git uses {}",
                    have.as_deref().unwrap_or("(unset)")
                ),
                _ => String::new(),
            };
            println!("{:<10} {}{note}", format!("{}:", f.label), f.want);
        }
    }
    if !ok {
        eprintln!("ndo4git: git is not using this identity; run `ndo4git apply`");
    }
    Ok(if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

// ------------------------------------------------------------------ schema

fn arg_json(a: &clap::Arg) -> serde_json::Value {
    serde_json::json!({
        "name": a.get_id().as_str(),
        "long": a.get_long().map(|l| format!("--{l}")),
        "short": a.get_short().map(|c| format!("-{c}")),
        "positional": a.is_positional(),
        "required": a.is_required_set(),
        "takes_value": a.get_action().takes_values(),
        "value_name": a.get_value_names().and_then(|v| v.first()).map(ToString::to_string),
        "env": a.get_env().map(|e| e.to_string_lossy().into_owned()),
        "help": a.get_help().map(ToString::to_string),
    })
}

fn command_json(c: &clap::Command, path: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for sub in c.get_subcommands().filter(|s| !s.is_hide_set()) {
        if sub.get_name() == "help" {
            continue;
        }
        let p = if path.is_empty() {
            sub.get_name().to_owned()
        } else {
            format!("{path} {}", sub.get_name())
        };
        let args: Vec<_> = sub
            .get_arguments()
            .filter(|a| !a.is_hide_set() && !a.is_global_set())
            .filter(|a| !matches!(a.get_id().as_str(), "help" | "version"))
            .map(arg_json)
            .collect();
        let nested = command_json(sub, &p);
        out.push(serde_json::json!({
            "command": p,
            "about": sub.get_about().map(ToString::to_string),
            "args": args,
            "has_json_output": sub.get_arguments().any(|a| a.get_id().as_str() == "json"),
        }));
        out.extend(nested);
    }
    out
}

/// Machine-readable description of the CLI, generated from the clap definitions
/// so it can never drift from the real options.
fn cmd_schema() -> Result<ExitCode> {
    let root = Cli::command();
    let global: Vec<_> = root
        .get_arguments()
        .filter(|a| a.is_global_set() && !matches!(a.get_id().as_str(), "help" | "version"))
        .map(arg_json)
        .collect();
    print_json(&serde_json::json!({
        "name": "ndo4git",
        "version": env!("CARGO_PKG_VERSION"),
        "about": root.get_about().map(ToString::to_string),
        "global_options": global,
        "commands": command_json(&root, ""),
        "exit_codes": {
            "0": "success",
            "1": "error (message on stderr)",
            "2": "`new`: a key already exists (use --rotate); `plan --check`: changes pending"
        },
        "conventions": [
            "commands with --json write JSON to stdout only; diagnostics and errors go to stderr",
            "repository arguments accept OWNER/REPO, GROUP/SUB/PROJECT, HOST/PATH or a clone URL",
            "no command prompts unless a backup passphrase is needed (NDO4GIT_BACKUP_PASSPHRASE or --passphrase-file avoid it)",
            "apply and plan are idempotent; rollback undoes the last apply"
        ],
        "environment": [
            "NDO4GIT_MANIFEST", "NDO4GIT_BACKUP_PASSPHRASE", "NDO4GIT_DEBUG",
            "NDO4GIT_SSH", "NDO4GIT_SUDO_USER_HOME", "XDG_CONFIG_HOME"
        ],
    }))?;
    Ok(ExitCode::SUCCESS)
}
