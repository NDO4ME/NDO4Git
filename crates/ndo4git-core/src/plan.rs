//! Plan / apply / rollback: reconcile the manifest with the real state.
//!
//! * [`desired`] turns a [`Manifest`] into the state it asks for (pure).
//! * [`gather`] reads the current state (database + derived files + git).
//! * [`diff`] compares both and returns ordered [`Action`]s (pure, unit-tested).
//! * [`apply`] executes them, journaling every step so [`rollback`] can undo
//!   the last run, even if it stopped half-way.
//!
//! Nothing here runs on the `ssh-wrapper` hot path. Git itself evaluates the
//! generated `includeIf` rules, so identities cost no process time at all.

use crate::crypto::{record_aad, MasterKey};
use crate::db::{Db, NewKey};
use crate::error::{Error, IoContext, Result};
use crate::exec::HostKeyPolicy;
use crate::forge::Forge;
use crate::install::write_atomic;
use crate::keygen;
use crate::manifest::{parse_match, resolve_ref, Identity, Manifest};
use crate::repo::{normalize_host, normalize_repo, DEFAULT_HOST, DEFAULT_HOSTS};
use crate::util::{hostname, now_unix};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const DERIVED_DIR: &str = "derived";
pub const MAIN_FILE: &str = "main.gitconfig";
pub const JOURNAL_FILE: &str = "last-apply.json";
const LOCK_FILE: &str = "apply.lock";

fn bad(m: impl Into<String>) -> Error {
    Error::Invalid(m.into())
}

/// One reconciliation step. Every variant carries what is needed to undo it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Action {
    HostSet {
        host: String,
        forge: String,
        was_managed: bool,
        prev_forge: Option<String>,
    },
    HostRemove {
        host: String,
        forge: String,
    },
    Hostkey {
        from: String,
        to: String,
    },
    KeyCreate {
        host: String,
        repo: String,
    },
    AliasSet {
        host: String,
        alias: String,
        target: String,
        prev_target: Option<String>,
    },
    AliasRemove {
        host: String,
        alias: String,
        target: String,
    },
    FileWrite {
        name: String,
        content: String,
        prev: Option<String>,
    },
    FileRemove {
        name: String,
        prev: String,
    },
    IncludeAdd {
        path: String,
    },
    IncludeRemove {
        path: String,
    },
}

impl Action {
    /// `+` create, `~` change, `-` remove.
    #[must_use]
    pub fn symbol(&self) -> char {
        match self {
            Self::KeyCreate { .. } | Self::IncludeAdd { .. } => '+',
            Self::HostSet { was_managed, .. } => {
                if *was_managed {
                    '~'
                } else {
                    '+'
                }
            }
            Self::AliasSet { prev_target, .. } => {
                if prev_target.is_some() {
                    '~'
                } else {
                    '+'
                }
            }
            Self::FileWrite { prev, .. } => {
                if prev.is_some() {
                    '~'
                } else {
                    '+'
                }
            }
            Self::Hostkey { .. } => '~',
            Self::HostRemove { .. }
            | Self::AliasRemove { .. }
            | Self::FileRemove { .. }
            | Self::IncludeRemove { .. } => '-',
        }
    }

    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::HostSet { host, forge, .. } => format!("host {host} ({forge})"),
            Self::HostRemove { host, .. } => format!("host {host}"),
            Self::Hostkey { from, to } => format!("host-key policy {from} -> {to}"),
            Self::KeyCreate { host, repo } => format!("key {repo} on {host}"),
            Self::AliasSet {
                host,
                alias,
                target,
                ..
            } => format!("alias {alias} -> {target} on {host}"),
            Self::AliasRemove { host, alias, .. } => format!("alias {alias} on {host}"),
            Self::FileWrite { name, .. } | Self::FileRemove { name, .. } => {
                format!("file {DERIVED_DIR}/{name}")
            }
            Self::IncludeAdd { path } | Self::IncludeRemove { path } => {
                format!("~/.gitconfig include.path = {path}")
            }
        }
    }
}

/// What the manifest asks for.
#[derive(Debug, Clone, Default)]
pub struct Desired {
    /// host -> forge name
    pub hosts: BTreeMap<String, String>,
    pub hostkey: Option<String>,
    /// (host, repo)
    pub keys: BTreeSet<(String, String)>,
    /// (host, alias) -> target
    pub aliases: BTreeMap<(String, String), String>,
    /// derived file name -> content
    pub files: BTreeMap<String, String>,
    pub prune: bool,
}

/// What exists now.
#[derive(Debug, Clone, Default)]
pub struct State {
    pub hosts: BTreeMap<String, String>,
    pub hostkey: String,
    pub keys: BTreeSet<(String, String)>,
    pub aliases: BTreeMap<(String, String), String>,
    pub files: BTreeMap<String, String>,
    pub include_present: bool,
}

/// Environment for the operations that touch git and the data directory.
pub struct Ctx<'a> {
    pub dir: &'a Path,
    /// Extra environment for `git` (tests point `GIT_CONFIG_GLOBAL` at a temp file).
    pub git_env: &'a [(String, String)],
}

impl Ctx<'_> {
    #[must_use]
    pub fn derived_dir(&self) -> PathBuf {
        self.dir.join(DERIVED_DIR)
    }

    pub fn include_path(&self) -> Result<String> {
        self.derived_dir()
            .join(MAIN_FILE)
            .into_os_string()
            .into_string()
            .map_err(|_| bad("the data directory path is not valid UTF-8"))
    }
}

// ---------------------------------------------------------------- rendering

/// Quote a gitconfig value. Control characters are rejected earlier.
fn q(v: &str) -> String {
    let mut o = String::with_capacity(v.len() + 2);
    o.push('"');
    for c in v.chars() {
        if c == '"' || c == '\\' {
            o.push('\\');
        }
        o.push(c);
    }
    o.push('"');
    o
}

fn identity_file(i: &Identity) -> String {
    let mut s = String::from("# Generated by `ndo4git apply` from manifest.toml. Do not edit.\n");
    if i.name.is_some() || i.email.is_some() || i.signing_key.is_some() {
        s.push_str("[user]\n");
        if let Some(n) = &i.name {
            let _ = writeln!(s, "\tname = {}", q(n));
        }
        if let Some(e) = &i.email {
            let _ = writeln!(s, "\temail = {}", q(e));
        }
        if let Some(k) = &i.signing_key {
            let _ = writeln!(s, "\tsigningkey = {}", q(k));
        }
    }
    if i.signing_key.is_some() {
        s.push_str("[gpg]\n\tformat = \"ssh\"\n[commit]\n\tgpgsign = \"true\"\n");
    }
    s
}

/// Make a glob case-insensitive: git's `hasconfig` is case-sensitive, but its
/// wildmatch understands `[aA]`, and URLs keep whatever case the user typed.
fn fold_case(glob: &str) -> String {
    let mut out = String::with_capacity(glob.len() * 3);
    for c in glob.chars() {
        if c.is_ascii_alphabetic() {
            out.push('[');
            out.push(c.to_ascii_lowercase());
            out.push(c.to_ascii_uppercase());
            out.push(']');
        } else {
            out.push(c);
        }
    }
    out
}

/// Git's `hasconfig` wildcard `*` does not cross `/`, but `**` as a whole path
/// segment does. Manifest globs let `*` span segments, so every whole-segment
/// `*` after the first becomes `**`; a bare `*` also gets a nested variant.
fn widen(pat: &str) -> Vec<String> {
    let segs: Vec<&str> = pat.split('/').collect();
    let widened: Vec<&str> = segs
        .iter()
        .enumerate()
        .map(|(i, s)| if i > 0 && *s == "*" { "**" } else { *s })
        .collect();
    let mut out = vec![widened.join("/")];
    if segs.len() == 1 && segs[0] == "*" {
        out.push("*/**".to_owned());
    }
    out
}

/// `hasconfig:remote.*.url:` patterns that cover every URL spelling of a match
/// (scp-like, `ssh://` with or without a port, `https://`, with or without
/// user and `.git`).
fn url_patterns(host: &str, pat: &str) -> Vec<String> {
    let host = fold_case(host);
    let mut out = Vec::new();
    for pat in widen(pat) {
        let pat = fold_case(&pat);
        let suffixes: &[&str] = if pat.ends_with('*') {
            &[""]
        } else {
            &["", ".[gG][iI][tT]"]
        };
        for suf in suffixes {
            for prefix in [
                format!("*@{host}:"),
                format!("{host}:"),
                format!("*://{host}/"),
                format!("*://*@{host}/"),
                format!("*://{host}:*/"),
                format!("*://*@{host}:*/"),
            ] {
                out.push(format!("{prefix}{pat}{suf}"));
            }
        }
    }
    out
}

/// `[section "sub"]` groups of `(key, value)`.
type Groups<'a> = BTreeMap<(String, Option<String>), Vec<(String, &'a str)>>;

fn settings_block(settings: &BTreeMap<String, String>) -> Result<String> {
    let mut groups = Groups::new();
    for (name, value) in settings {
        let parts: Vec<&str> = name.split('.').collect();
        let (section, sub, key) = match parts.as_slice() {
            [sec, key] => ((*sec).to_owned(), None, (*key).to_owned()),
            [sec, sub, key] => (
                (*sec).to_owned(),
                Some((*sub).to_owned()),
                (*key).to_owned(),
            ),
            _ => return Err(bad(format!("invalid git setting {name:?}"))),
        };
        groups.entry((section, sub)).or_default().push((key, value));
    }
    let mut out = String::new();
    for ((section, sub), kvs) in groups {
        match sub {
            Some(sub) => {
                let _ = writeln!(out, "[{section} {}]", q(&sub));
            }
            None => {
                let _ = writeln!(out, "[{section}]");
            }
        }
        for (key, value) in kvs {
            let _ = writeln!(out, "\t{key} = {}", q(value));
        }
    }
    Ok(out)
}

fn include_blocks(ids: &[Identity], derived: &Path) -> Result<String> {
    let mut out = String::new();
    for id in ids {
        let file = derived
            .join(identity_name(&id.id))
            .into_os_string()
            .into_string()
            .map_err(|_| bad("the data directory path is not valid UTF-8"))?;
        for spec in &id.matches {
            let (host, pat) = parse_match(spec)?;
            for url in url_patterns(&host, &pat) {
                let _ = writeln!(
                    out,
                    "[includeIf {}]\n\tpath = {}",
                    q(&format!("hasconfig:remote.*.url:{url}")),
                    q(&file)
                );
            }
        }
    }
    Ok(out)
}

fn main_file(manifest: &Manifest, derived: &Path) -> Result<String> {
    let settings = manifest.effective_settings();
    if settings.is_empty() && manifest.identities.is_empty() {
        return Ok(String::new());
    }
    let mut out = String::from(
        "# Generated by `ndo4git apply` from manifest.toml. Do not edit; edit the manifest.\n",
    );
    out.push_str(&settings_block(&settings)?);
    out.push_str(&include_blocks(&manifest.identities, derived)?);
    Ok(out)
}

fn identity_name(id: &str) -> String {
    format!("id-{id}.gitconfig")
}

/// Derived file names are generated by us; anything else (e.g. from a tampered journal) is refused.
fn safe_name(n: &str) -> Result<&str> {
    let ok = n.ends_with(".gitconfig")
        && n.len() <= 80
        && n.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
        && !n.starts_with('.');
    if ok {
        Ok(n)
    } else {
        Err(bad(format!("refusing unexpected derived file name {n:?}")))
    }
}

/// Compute the desired state. `derived` is the absolute derived directory.
pub fn desired(m: &Manifest, derived: &Path) -> Result<Desired> {
    let mut d = Desired {
        prune: m.prune,
        hostkey: m
            .hostkey
            .as_deref()
            .and_then(HostKeyPolicy::parse)
            .map(|p| p.name().to_owned()),
        ..Desired::default()
    };
    for h in DEFAULT_HOSTS {
        d.hosts
            .insert(h.to_owned(), Forge::detect(h).name().to_owned());
    }
    for (h, f) in &m.hosts {
        let forge = Forge::parse(f).ok_or_else(|| bad(format!("unknown forge {f:?}")))?;
        d.hosts
            .insert(h.to_ascii_lowercase(), forge.name().to_owned());
    }
    for k in &m.keys {
        let (h, r) = resolve_ref(k)?;
        d.hosts
            .entry(h.clone())
            .or_insert_with(|| Forge::detect(&h).name().to_owned());
        d.keys.insert((h, r));
    }
    for (a, t) in &m.aliases {
        let (h, ra) = resolve_ref(a)?;
        let (_, rt) = resolve_ref(t)?;
        d.hosts
            .entry(h.clone())
            .or_insert_with(|| Forge::detect(&h).name().to_owned());
        d.aliases.insert((h, ra), rt);
    }
    let main = main_file(m, derived)?;
    if !main.is_empty() {
        d.files.insert(MAIN_FILE.to_owned(), main);
        for i in &m.identities {
            d.files.insert(identity_name(&i.id), identity_file(i));
        }
    }
    Ok(d)
}

// ---------------------------------------------------------------- diff

/// Compare `want` with `have`. Order matters: hosts, host-key policy, keys,
/// aliases, then files, with the git include added last and removed first,
/// so git never points at a file that does not exist.
pub fn diff(want: &Desired, have: &State, include_path: &str) -> Result<Vec<Action>> {
    let mut out = diff_hosts(want, have);
    for (host, repo) in &want.keys {
        if !have.keys.contains(&(host.clone(), repo.clone())) {
            out.push(Action::KeyCreate {
                host: host.clone(),
                repo: repo.clone(),
            });
        }
    }
    diff_aliases(want, have, &mut out)?;
    diff_files(want, have, include_path, &mut out);
    Ok(out)
}

fn diff_hosts(want: &Desired, have: &State) -> Vec<Action> {
    let mut out = Vec::new();
    for (host, forge) in &want.hosts {
        match have.hosts.get(host) {
            Some(f) if f == forge => {}
            other => out.push(Action::HostSet {
                host: host.clone(),
                forge: forge.clone(),
                was_managed: other.is_some(),
                prev_forge: other.cloned(),
            }),
        }
    }
    if want.prune {
        for (host, forge) in &have.hosts {
            if !want.hosts.contains_key(host) {
                out.push(Action::HostRemove {
                    host: host.clone(),
                    forge: forge.clone(),
                });
            }
        }
    }
    if let Some(to) = &want.hostkey {
        if *to != have.hostkey {
            out.push(Action::Hostkey {
                from: have.hostkey.clone(),
                to: to.clone(),
            });
        }
    }
    out
}

fn diff_aliases(want: &Desired, have: &State, out: &mut Vec<Action>) -> Result<()> {
    let will_have_key = |h: &str, r: &str| {
        let k = (h.to_owned(), r.to_owned());
        have.keys.contains(&k) || want.keys.contains(&k)
    };
    for ((host, alias), target) in &want.aliases {
        if will_have_key(host, alias) {
            return Err(bad(format!(
                "alias {alias} on {host} conflicts with a key for the same repository; remove one of them"
            )));
        }
        if !will_have_key(host, target) {
            return Err(bad(format!(
                "alias {alias} -> {target} on {host}: the target has no key; add it to `keys`"
            )));
        }
        let cur = have.aliases.get(&(host.clone(), alias.clone()));
        if cur != Some(target) {
            out.push(Action::AliasSet {
                host: host.clone(),
                alias: alias.clone(),
                target: target.clone(),
                prev_target: cur.cloned(),
            });
        }
    }
    if want.prune {
        for ((host, alias), target) in &have.aliases {
            if !want.aliases.contains_key(&(host.clone(), alias.clone())) {
                out.push(Action::AliasRemove {
                    host: host.clone(),
                    alias: alias.clone(),
                    target: target.clone(),
                });
            }
        }
    }
    Ok(())
}

fn diff_files(want: &Desired, have: &State, include_path: &str, out: &mut Vec<Action>) {
    let want_include = want.files.contains_key(MAIN_FILE);
    if have.include_present && !want_include {
        out.push(Action::IncludeRemove {
            path: include_path.to_owned(),
        });
    }
    for (name, content) in &want.files {
        match have.files.get(name) {
            Some(c) if c == content => {}
            prev => out.push(Action::FileWrite {
                name: name.clone(),
                content: content.clone(),
                prev: prev.cloned(),
            }),
        }
    }
    for (name, prev) in &have.files {
        if !want.files.contains_key(name) {
            out.push(Action::FileRemove {
                name: name.clone(),
                prev: prev.clone(),
            });
        }
    }
    if want_include && !have.include_present {
        out.push(Action::IncludeAdd {
            path: include_path.to_owned(),
        });
    }
}

// ---------------------------------------------------------------- state

fn git(env: &[(String, String)], args: &[&str]) -> Result<std::process::Output> {
    let mut c = Command::new("git");
    c.args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().ctx("running git (is it installed?)")
}

/// `hasconfig:` in `includeIf` needs git 2.36 or newer.
pub fn require_hasconfig(env: &[(String, String)]) -> Result<()> {
    let o = git(env, &["--version"])?;
    let out = String::from_utf8_lossy(&o.stdout);
    let v: Vec<u32> = out
        .split_whitespace()
        .find(|w| w.starts_with(|c: char| c.is_ascii_digit()))
        .unwrap_or("")
        .split('.')
        .take(2)
        .map_while(|n| n.parse().ok())
        .collect();
    match v.as_slice() {
        [maj, min] if (*maj, *min) >= (2, 36) => Ok(()),
        [maj, _] if *maj > 2 => Ok(()),
        _ => Err(bad(format!(
            "identities need git 2.36 or newer (includeIf hasconfig); found {:?}",
            out.trim()
        ))),
    }
}

fn include_is_set(env: &[(String, String)], path: &str) -> Result<bool> {
    let o = git(env, &["config", "--global", "--get-all", "include.path"])?;
    match o.status.code() {
        Some(0) => Ok(String::from_utf8_lossy(&o.stdout)
            .lines()
            .any(|l| l == path)),
        Some(1) => Ok(false),
        _ => Err(bad(format!(
            "git config --global failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ))),
    }
}

fn include_add(env: &[(String, String)], path: &str) -> Result<()> {
    if include_is_set(env, path)? {
        return Ok(());
    }
    let o = git(env, &["config", "--global", "--add", "include.path", path])?;
    if o.status.success() {
        Ok(())
    } else {
        Err(bad(format!(
            "git config --global failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )))
    }
}

fn include_remove(env: &[(String, String)], path: &str) -> Result<()> {
    // A regex anchored on the literal path: `--fixed-value` needs git >= 2.30.
    let mut re = String::with_capacity(path.len() + 2);
    re.push('^');
    for c in path.chars() {
        if "\\.[]{}()*+?^$|".contains(c) {
            re.push('\\');
        }
        re.push(c);
    }
    re.push('$');
    let o = git(
        env,
        &["config", "--global", "--unset-all", "include.path", &re],
    )?;
    // exit 5: not present
    if o.status.success() || o.status.code() == Some(5) {
        Ok(())
    } else {
        Err(bad(format!(
            "git config --global failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )))
    }
}

/// Read the current state.
pub fn gather(ctx: &Ctx<'_>, db: &Db) -> Result<State> {
    let mut st = State {
        hostkey: db.hostkey_policy()?.name().to_owned(),
        ..State::default()
    };
    for h in db.hosts()? {
        let f = db.forge(&h)?.name().to_owned();
        st.hosts.insert(h, f);
    }
    for k in db.list_keys()? {
        st.keys.insert((k.host, k.repo));
    }
    for a in db.list_aliases()? {
        st.aliases.insert((a.host, a.alias), a.target);
    }
    let derived = ctx.derived_dir();
    if let Ok(rd) = fs::read_dir(&derived) {
        for e in rd.flatten() {
            let Some(name) = e.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if safe_name(&name).is_err() {
                continue; // not ours
            }
            let is_file = e.file_type().is_ok_and(|t| t.is_file());
            let content = if is_file {
                fs::read_to_string(e.path()).unwrap_or_default()
            } else {
                String::new()
            };
            st.files.insert(name, content);
        }
    }
    st.include_present = include_is_set(ctx.git_env, &ctx.include_path()?)?;
    Ok(st)
}

/// Compute the plan for `manifest` against the live state.
pub fn plan(ctx: &Ctx<'_>, db: &Db, m: &Manifest) -> Result<Vec<Action>> {
    let want = desired(m, &ctx.derived_dir())?;
    let have = gather(ctx, db)?;
    diff(&want, &have, &ctx.include_path()?)
}

// ---------------------------------------------------------------- apply / rollback

#[derive(Debug, Serialize, Deserialize)]
pub struct Journal {
    pub version: u32,
    pub applied_at: i64,
    pub actions: Vec<Action>,
}

fn journal_path(dir: &Path) -> PathBuf {
    dir.join(JOURNAL_FILE)
}

fn save_journal(dir: &Path, actions: &[Action]) -> Result<()> {
    let j = Journal {
        version: 1,
        applied_at: now_unix(),
        actions: actions.to_vec(),
    };
    write_atomic(&journal_path(dir), &serde_json::to_vec_pretty(&j)?, 0o600)
}

/// The last journal, if any.
pub fn load_journal(dir: &Path) -> Result<Option<Journal>> {
    match fs::read(journal_path(dir)) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).ctx("reading last-apply.json"),
    }
}

fn write_derived(ctx: &Ctx<'_>, name: &str, content: &str) -> Result<()> {
    let name = safe_name(name)?;
    let dir = ctx.derived_dir();
    if !dir.is_dir() {
        match fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e).ctx(format!("creating {}", dir.display())),
        }
    }
    write_atomic(&dir.join(name), content.as_bytes(), 0o600)
}

fn remove_derived(ctx: &Ctx<'_>, name: &str) -> Result<()> {
    let name = safe_name(name)?;
    let p = ctx.derived_dir().join(name);
    match fs::remove_file(&p) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).ctx(format!("removing {}", p.display())),
    }
}

fn set_host(db: &Db, host: &str, forge: &str, managed: bool) -> Result<()> {
    let f = Forge::parse(forge).ok_or_else(|| bad(format!("unknown forge {forge:?}")))?;
    let mut hosts = db.hosts()?;
    if managed && !hosts.iter().any(|h| h == host) {
        hosts.push(host.to_owned());
        db.set_hosts(&hosts)?;
    }
    db.set_forge(host, f)
}

fn unmanage_host(db: &Db, host: &str) -> Result<()> {
    let hosts: Vec<String> = db.hosts()?.into_iter().filter(|h| h != host).collect();
    db.set_hosts(&hosts)
}

fn create_key(
    dir: &Path,
    db: &mut Db,
    master: &mut Option<MasterKey>,
    host: &str,
    repo: &str,
) -> Result<()> {
    if master.is_none() {
        *master = Some(MasterKey::load_or_create(dir)?);
    }
    let Some(master) = master.as_ref() else {
        return Err(bad("master key unavailable"));
    };
    let material = keygen::generate(&keygen::default_comment(repo, &hostname()))?;
    let aad = record_aad(repo, host, &material.algo);
    let (enc, nonce) = master.seal(&aad, material.private_openssh.as_bytes())?;
    db.insert_key(&NewKey {
        repo,
        host,
        algo: &material.algo,
        public_key: &material.public_openssh,
        private_key_enc: &enc,
        nonce: &nonce,
        fingerprint: &material.fingerprint,
        can_write: false,
        created_at: now_unix(),
        last_used_at: None,
    })?;
    Ok(())
}

fn do_action(ctx: &Ctx<'_>, db: &mut Db, master: &mut Option<MasterKey>, a: &Action) -> Result<()> {
    match a {
        Action::HostSet { host, forge, .. } => set_host(db, host, forge, true),
        Action::HostRemove { host, .. } => unmanage_host(db, host),
        Action::Hostkey { to, .. } => db.set_hostkey_policy(
            HostKeyPolicy::parse(to).ok_or_else(|| bad(format!("bad policy {to:?}")))?,
        ),
        Action::KeyCreate { host, repo } => create_key(ctx.dir, db, master, host, repo),
        Action::AliasSet {
            host,
            alias,
            target,
            ..
        } => db.add_alias(alias, target, host, now_unix()),
        Action::AliasRemove { host, alias, .. } => db.remove_alias(alias, host).map(|_| ()),
        Action::FileWrite { name, content, .. } => write_derived(ctx, name, content),
        Action::FileRemove { name, .. } => remove_derived(ctx, name),
        Action::IncludeAdd { path } => include_add(ctx.git_env, path),
        Action::IncludeRemove { path } => include_remove(ctx.git_env, path),
    }
}

/// Undo one action. `Ok(Some(msg))` means it was deliberately skipped.
fn undo_action(ctx: &Ctx<'_>, db: &mut Db, a: &Action) -> Result<Option<String>> {
    match a {
        Action::HostSet {
            host,
            was_managed,
            prev_forge,
            ..
        } => {
            if *was_managed {
                if let Some(f) = prev_forge {
                    set_host(db, host, f, true)?;
                }
            } else {
                unmanage_host(db, host)?;
            }
        }
        Action::HostRemove { host, forge } => set_host(db, host, forge, true)?,
        Action::Hostkey { from, .. } => db.set_hostkey_policy(
            HostKeyPolicy::parse(from).ok_or_else(|| bad(format!("bad policy {from:?}")))?,
        )?,
        Action::KeyCreate { host, repo } => {
            // A key that has been used (or may be registered on a forge by now) is
            // never deleted by a late rollback; remove it explicitly with `rm`.
            if db
                .get_key(repo, host)?
                .is_some_and(|k| k.last_used_at.is_some())
            {
                return Ok(Some(format!(
                    "kept key {repo} on {host}: it has been used since; delete it with `ndo4git rm {repo}` if you want it gone"
                )));
            }
            db.delete_key(repo, host)?;
        }
        Action::AliasSet {
            host,
            alias,
            prev_target,
            ..
        } => match prev_target {
            Some(t) => db.add_alias(alias, t, host, now_unix())?,
            None => {
                db.remove_alias(alias, host)?;
            }
        },
        Action::AliasRemove {
            host,
            alias,
            target,
        } => db.add_alias(alias, target, host, now_unix())?,
        Action::FileWrite { name, prev, .. } => match prev {
            Some(p) => write_derived(ctx, name, p)?,
            None => remove_derived(ctx, name)?,
        },
        Action::FileRemove { name, prev } => write_derived(ctx, name, prev)?,
        Action::IncludeAdd { path } => include_remove(ctx.git_env, path)?,
        Action::IncludeRemove { path } => include_add(ctx.git_env, path)?,
    }
    Ok(None)
}

/// The journal is a file on disk: before acting on it, make sure every value
/// is something `apply` could have produced. Fail closed on anything else.
fn validate_journal(ctx: &Ctx<'_>, actions: &[Action]) -> Result<()> {
    let include = ctx.include_path()?;
    for a in actions {
        match a {
            Action::HostSet { host, forge, .. } | Action::HostRemove { host, forge } => {
                normalize_host(host)?;
                if Forge::parse(forge).is_none() {
                    return Err(bad(format!("journal: unknown forge {forge:?}")));
                }
            }
            Action::Hostkey { from, to } => {
                if HostKeyPolicy::parse(from).is_none() || HostKeyPolicy::parse(to).is_none() {
                    return Err(bad("journal: unknown host-key policy"));
                }
            }
            Action::KeyCreate { host, repo } => {
                normalize_host(host)?;
                normalize_repo(repo)?;
            }
            Action::AliasSet {
                host,
                alias,
                target,
                prev_target,
            } => {
                normalize_host(host)?;
                normalize_repo(alias)?;
                normalize_repo(target)?;
                if let Some(t) = prev_target {
                    normalize_repo(t)?;
                }
            }
            Action::AliasRemove {
                host,
                alias,
                target,
            } => {
                normalize_host(host)?;
                normalize_repo(alias)?;
                normalize_repo(target)?;
            }
            Action::FileWrite { name, .. } | Action::FileRemove { name, .. } => {
                safe_name(name)?;
            }
            Action::IncludeAdd { path } | Action::IncludeRemove { path } => {
                if *path != include {
                    return Err(bad(format!(
                        "journal: unexpected include path {path:?}; refusing to touch your git config"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Hold this for the whole plan + apply (or rollback) so two runs cannot interleave.
pub fn lock(dir: &Path) -> Result<nix::fcntl::Flock<fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join(LOCK_FILE);
    let f = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .custom_flags(crate::paths::o_nofollow())
        .open(&path)
        .ctx(format!("opening {}", path.display()))?;
    nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusiveNonblock).map_err(|_| {
        bad("another `ndo4git apply` or `rollback` is running; try again when it has finished")
    })
}

/// Execute `actions` in order. The journal is written even when a step fails,
/// so [`rollback`] can undo what already happened.
pub fn apply(ctx: &Ctx<'_>, db: &mut Db, actions: &[Action]) -> Result<()> {
    if actions.is_empty() {
        return Ok(());
    }
    let mut master = None;
    let mut done: Vec<Action> = Vec::new();
    for a in actions {
        match do_action(ctx, db, &mut master, a) {
            Ok(()) => done.push(a.clone()),
            Err(e) => {
                if !done.is_empty() {
                    save_journal(ctx.dir, &done)?;
                }
                return Err(bad(format!(
                    "{}: {e}{}",
                    a.describe(),
                    if done.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "; {} earlier step(s) were applied, run `ndo4git rollback` to undo them",
                            done.len()
                        )
                    }
                )));
            }
        }
    }
    save_journal(ctx.dir, &done)
}

/// Result of [`rollback`].
#[derive(Debug, Serialize)]
pub struct RollbackReport {
    pub reverted: Vec<Action>,
    /// Steps that were deliberately not undone, with the reason.
    pub warnings: Vec<String>,
}

/// Undo the last [`apply`].
pub fn rollback(ctx: &Ctx<'_>, db: &mut Db) -> Result<RollbackReport> {
    let Some(j) = load_journal(ctx.dir)? else {
        return Err(bad("nothing to roll back (no previous apply)"));
    };
    validate_journal(ctx, &j.actions)?;
    let mut warnings = Vec::new();
    for a in j.actions.iter().rev() {
        let w =
            undo_action(ctx, db, a).map_err(|e| bad(format!("undoing {}: {e}", a.describe())))?;
        warnings.extend(w);
    }
    let _ = fs::remove_file(journal_path(ctx.dir));
    Ok(RollbackReport {
        reverted: j.actions,
        warnings,
    })
}

// ---------------------------------------------------------------- init

fn toml_str(s: &str) -> Result<String> {
    if s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
    {
        Ok(format!("\"{s}\""))
    } else {
        Err(bad(format!("cannot write {s:?} into a manifest")))
    }
}

fn short_ref(host: &str, repo: &str) -> String {
    if host == DEFAULT_HOST {
        repo.to_owned()
    } else {
        format!("{host}/{repo}")
    }
}

/// A starter manifest that reproduces the current state (so `plan` is empty).
pub fn init_manifest(st: &State) -> Result<String> {
    let mut s = String::from(
        "# ndo4git manifest: the single source of truth.\n\
         # `ndo4git plan` shows what would change, `ndo4git apply` does it, `ndo4git rollback` undoes the last apply.\n\
         version = 1\n\n\
         # Conservative performance preset (parallel fetch, commit-graph, no `ssh -G` probe, ...).\n\
         perf = false\n\n\
         # true: also remove hosts and aliases that are not listed here (keys are never deleted).\n\
         prune = false\n\n",
    );
    let _ = writeln!(s, "hostkey = {}\n", toml_str(&st.hostkey)?);
    let extra: Vec<_> = st
        .hosts
        .iter()
        .filter(|(h, f)| !DEFAULT_HOSTS.contains(&h.as_str()) || **f != Forge::detect(h).name())
        .collect();
    // top-level keys must precede every [table]
    s.push_str(
        "# Repositories that must have a key: \"OWNER/REPO\" (GitHub) or \"HOST/PATH\".\nkeys = [\n",
    );
    for (h, r) in &st.keys {
        let _ = writeln!(s, "  {},", toml_str(&short_ref(h, r))?);
    }
    s.push_str("]\n\n[hosts]\n");
    for (h, f) in extra {
        let _ = writeln!(s, "{} = {}", toml_str(h)?, toml_str(f)?);
    }
    s.push_str("\n# A renamed repository uses the key of its new name.\n[aliases]\n");
    for ((h, a), t) in &st.aliases {
        let _ = writeln!(
            s,
            "{} = {}",
            toml_str(&short_ref(h, a))?,
            toml_str(&short_ref(h, t))?
        );
    }
    s.push_str(
        "\n# Git identities, applied by git itself through includeIf (no runtime cost).\n\
         # The last matching entry wins.\n\
         #\n\
         # [[identity]]\n\
         # id = \"work\"\n\
         # name = \"Ada Lovelace\"\n\
         # email = \"ada@example.com\"\n\
         # signing_key = \"~/.ssh/id_ed25519.pub\"   # optional: sign commits with SSH\n\
         # match = [\"github.com/acme/*\"]\n\
         #\n\
         # Extra git settings (performance/workflow keys only):\n\
         # [settings]\n\
         # \"pull.rebase\" = \"true\"\n",
    );
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn want() -> Desired {
        let m = Manifest::parse(
            r#"
version = 1
keys = ["acme/widget"]
[aliases]
"acme/old" = "acme/widget"
[[identity]]
id = "work"
email = "a@b.example"
match = ["github.com/acme/*"]
"#,
        )
        .unwrap();
        desired(&m, Path::new("/cfg/derived")).unwrap()
    }

    fn empty_state() -> State {
        let mut s = State {
            hostkey: "accept-new".into(),
            ..State::default()
        };
        for h in DEFAULT_HOSTS {
            s.hosts
                .insert(h.to_owned(), Forge::detect(h).name().to_owned());
        }
        s
    }

    #[test]
    fn plan_from_scratch_is_ordered() {
        let acts = diff(&want(), &empty_state(), "/cfg/derived/main.gitconfig").unwrap();
        let kinds: Vec<&str> = acts
            .iter()
            .map(|a| match a {
                Action::KeyCreate { .. } => "key",
                Action::AliasSet { .. } => "alias",
                Action::FileWrite { .. } => "file",
                Action::IncludeAdd { .. } => "include",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, ["key", "alias", "file", "file", "include"]);
    }

    #[test]
    fn converged_state_has_empty_plan() {
        let w = want();
        let mut s = empty_state();
        s.keys.insert(("github.com".into(), "acme/widget".into()));
        s.aliases.insert(
            ("github.com".into(), "acme/old".into()),
            "acme/widget".into(),
        );
        s.files = w.files.clone();
        s.include_present = true;
        assert!(diff(&w, &s, "/cfg/derived/main.gitconfig")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn removing_identities_removes_files_and_include_first() {
        let mut s = empty_state();
        s.files.insert(MAIN_FILE.into(), "x".into());
        s.files.insert("id-work.gitconfig".into(), "y".into());
        s.include_present = true;
        let w = Desired {
            hosts: s.hosts.clone(),
            ..Desired::default()
        };
        let acts = diff(&w, &s, "/p").unwrap();
        assert!(matches!(acts[0], Action::IncludeRemove { .. }));
        assert!(acts[1..]
            .iter()
            .all(|a| matches!(a, Action::FileRemove { .. })));
    }

    #[test]
    fn prune_only_when_asked() {
        let mut s = empty_state();
        s.hosts.insert("old.example".into(), "github".into());
        s.keys.insert(("github.com".into(), "a/b".into()));
        let mut w = Desired {
            hosts: empty_state().hosts,
            ..Desired::default()
        };
        assert!(diff(&w, &s, "/p").unwrap().is_empty());
        w.prune = true;
        let acts = diff(&w, &s, "/p").unwrap();
        assert_eq!(acts.len(), 1);
        assert!(matches!(&acts[0], Action::HostRemove { host, .. } if host == "old.example"));
    }

    #[test]
    fn alias_validation() {
        let mut w = Desired {
            hosts: empty_state().hosts,
            ..Desired::default()
        };
        w.aliases
            .insert(("github.com".into(), "a/old".into()), "a/new".into());
        assert!(diff(&w, &empty_state(), "/p").is_err(), "target has no key");
        w.keys.insert(("github.com".into(), "a/new".into()));
        assert!(diff(&w, &empty_state(), "/p").is_ok());
        w.keys.insert(("github.com".into(), "a/old".into()));
        assert!(diff(&w, &empty_state(), "/p").is_err(), "alias has own key");
    }

    #[test]
    fn rendered_includeif_covers_url_spellings() {
        let w = want();
        let main = &w.files[MAIN_FILE];
        for needle in [
            r#"[includeIf "hasconfig:remote.*.url:*@[gG][iI][tT][hH][uU][bB].[cC][oO][mM]:[aA][cC][mM][eE]/**"]"#,
            r#"[includeIf "hasconfig:remote.*.url:[gG][iI][tT][hH][uU][bB].[cC][oO][mM]:[aA][cC][mM][eE]/**"]"#,
            r#"[includeIf "hasconfig:remote.*.url:*://[gG][iI][tT][hH][uU][bB].[cC][oO][mM]/[aA][cC][mM][eE]/**"]"#,
            r#"[includeIf "hasconfig:remote.*.url:*://*@[gG][iI][tT][hH][uU][bB].[cC][oO][mM]/[aA][cC][mM][eE]/**"]"#,
        ] {
            assert!(main.contains(needle), "{needle}\n{main}");
        }
        assert!(main.contains(r#"path = "/cfg/derived/id-work.gitconfig""#));
        assert_eq!(
            w.files["id-work.gitconfig"],
            "# Generated by `ndo4git apply` from manifest.toml. Do not edit.\n[user]\n\temail = \"a@b.example\"\n"
        );
    }

    #[test]
    fn exact_match_also_covers_dot_git() {
        let p = url_patterns("a.b", "x/y");
        assert!(p.contains(&"*@[aA].[bB]:[xX]/[yY]".to_owned()));
        assert!(p.contains(&"*@[aA].[bB]:[xX]/[yY].[gG][iI][tT]".to_owned()));
    }

    #[test]
    fn values_are_quoted() {
        assert_eq!(q(r#"a"b\c"#), r#""a\"b\\c""#);
    }

    #[test]
    fn whole_segment_star_crosses_slashes_for_git() {
        // git's `*` stops at `/`; `**` as a segment spans nested groups.
        let p = url_patterns("gitlab.com", "grp/*");
        assert!(p.iter().any(|x| x.ends_with(":[gG][rR][pP]/**")), "{p:?}");
        assert!(p
            .iter()
            .any(|x| x.starts_with("*://*@[gG]") && x.contains(":*/")));
        let bare = url_patterns("gitlab.com", "*");
        assert!(bare.iter().any(|x| x.ends_with(":*/**")), "{bare:?}");
    }

    #[test]
    fn git_version_gate() {
        // The installed git of the test machine is far newer than 2.36.
        assert!(require_hasconfig(&[]).is_ok());
    }

    #[test]
    fn safe_names() {
        assert!(safe_name("main.gitconfig").is_ok());
        assert!(safe_name("id-work_1.gitconfig").is_ok());
        assert!(safe_name("../x.gitconfig").is_err());
        assert!(safe_name("a/b.gitconfig").is_err());
        assert!(safe_name(".x.gitconfig").is_err());
        assert!(safe_name("x.txt").is_err());
    }

    #[test]
    fn init_manifest_roundtrips_to_empty_plan() {
        let mut s = empty_state();
        s.hosts.insert("git.example.org".into(), "gitlab".into());
        s.keys.insert(("github.com".into(), "acme/widget".into()));
        s.keys
            .insert(("git.example.org".into(), "team/proj".into()));
        s.aliases.insert(
            ("github.com".into(), "acme/old".into()),
            "acme/widget".into(),
        );
        s.hostkey = "strict".into();
        let text = init_manifest(&s).unwrap();
        let m = Manifest::parse(&text).unwrap();
        let w = desired(&m, Path::new("/d")).unwrap();
        assert!(
            diff(&w, &s, "/d/main.gitconfig").unwrap().is_empty(),
            "{text}"
        );
    }
}
