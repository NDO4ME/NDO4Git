//! Command implementations.

use crate::cli::{Cli, Command, HostAction, Shell};
use crate::{prompt, render};
use anyhow::{bail, Context, Result};
use clap::{CommandFactory, Parser};
use comfy_table::{presets::UTF8_FULL_CONDENSED, Table};
use ndo4git_core::crypto::{record_aad, MasterKey};
use ndo4git_core::db::{Db, KeyRow, NewKey};
use ndo4git_core::doctor::{self, Status};
use ndo4git_core::exec::HostKeyPolicy;
use ndo4git_core::forge::Forge;
use ndo4git_core::install::Plan;
use ndo4git_core::repo::{normalize_host, parse_remote_url, parse_target, DEFAULT_HOST};
use ndo4git_core::util::{fmt_ts, hostname, now_unix};
use ndo4git_core::{backup, keygen, paths};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use zeroize::Zeroizing;

/// Exit code when `new` finds an existing key and `--rotate` was not given.
const EXIT_EXISTS: u8 = 2;

pub fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let sudo = cli.sudo_user_home;
    let host_flag = cli.host.as_deref();
    match cli.command {
        Command::New {
            target,
            rotate,
            write,
            comment,
            json,
        } => cmd_new(
            sudo,
            host_flag,
            target.as_deref(),
            rotate,
            write,
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
            write,
            comment,
        } => cmd_import(
            sudo,
            host_flag,
            &repo,
            &file,
            force,
            write,
            comment.as_deref(),
        ),
        Command::ExportPub { repo } => cmd_export_pub(sudo, host_flag, &repo),
        Command::ExportPrivate { repo, yes } => cmd_export_private(sudo, host_flag, &repo, yes),
        Command::Alias { old, new, remove } => cmd_alias(sudo, host_flag, &old, &new, remove),
        Command::Host { action } => cmd_host(sudo, action),
        Command::Doctor { json } => cmd_doctor(sudo, json),
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
        Command::Update {
            check,
            version,
            force,
        } => crate::update::run(check, version.as_deref(), force),
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
                Shell::Powershell => clap_complete::Shell::PowerShell,
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
    can_write: bool,
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
        can_write,
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
    write: bool,
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
        write,
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
    t.set_header([
        "REPO",
        "HOST",
        "FINGERPRINT",
        "WRITE",
        "CREATED",
        "LAST USED",
    ]);
    for k in &keys {
        t.add_row([
            k.repo.clone(),
            k.host.clone(),
            k.fingerprint.clone(),
            if k.can_write { "yes" } else { "no" }.to_owned(),
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
    println!("Write access: {}", if k.can_write { "yes" } else { "no" });
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
    write: bool,
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
        write,
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
        HostAction::List => {}
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

fn cmd_doctor(sudo: bool, json: bool) -> Result<ExitCode> {
    let checks = doctor::run(&Plan::system()?, sudo);
    if json {
        print_json(&checks)?;
    } else {
        let mut t = Table::new();
        t.load_preset(UTF8_FULL_CONDENSED);
        t.set_header(["", "CHECK", "DETAIL"]);
        for c in &checks {
            let s = match c.status {
                Status::Ok => "OK",
                Status::Warn => "WARN",
                Status::Fail => "FAIL",
            };
            t.add_row([s, c.name, c.detail.as_str()]);
        }
        println!("{t}");
    }
    let failed = checks.iter().any(|c| c.status == Status::Fail);
    Ok(if failed {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
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
