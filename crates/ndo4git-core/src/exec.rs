//! The hot path: what happens when git runs `ndo4git ssh-wrapper <ssh args>`.
//!
//! Flow: parse args → check host list → look up key (SQLite, read-mostly) →
//! decrypt → put the key in a sealed in-memory file → `exec` the real ssh.
//! **Any** failure at any step falls back to `exec ssh <original args>`.
//!
//! # `unsafe`
//! None. `memfd_create`, `fchmod`-equivalent and `execv` are all reached
//! through safe wrappers (`nix`, `std`).
//!
//! # Key hand-off
//! OpenSSH calls `closefrom()` at startup, so a descriptor inherited across
//! `exec` (`-i /proc/self/fd/N`) is gone before ssh reads the key. Instead the
//! wrapper starts a tiny *key holder* (`ndo4git __key-holder`, a re-exec of
//! this binary in its own process group). The holder receives the decrypted
//! key on stdin, stores it in an anonymous `memfd` (mode 0600; fallback: an
//! unlinked 0600 file in `$XDG_RUNTIME_DIR`, `/dev/shm` or `/tmp`), reports the
//! descriptor number, and stays alive until its parent dies. The wrapper then
//! `exec`s ssh with `-i /proc/<holder pid>/fd/N`; since `exec` keeps the pid,
//! the holder's parent *is* ssh, and the holder exits (also via
//! `PR_SET_PDEATHSIG`) as soon as ssh does. The git-visible process is still
//! plain ssh: exit codes and stdio pass straight through.
//!
//! On platforms without `memfd`/`/proc` (macOS) — or with
//! `NDO4GIT_KEY_STAGING=file` — the holder instead writes the key to a 0600
//! file inside a private 0700 per-user directory and deletes it the moment its
//! parent (ssh) is gone; leftovers from a crashed holder are swept on the next run.

use crate::crypto::{record_aad, MasterKey};
use crate::db::{Db, OpenMode};
use crate::error::{Error, IoContext, Result};
use crate::paths;
use crate::util::now_unix;
use crate::wrapper::{extract_repo_from_command, host_is_configured, parse_ssh_args};
#[cfg(target_os = "linux")]
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use std::ffi::{CString, OsString};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use zeroize::Zeroizing;

/// DB busy timeout on the hot path: never make `git` wait noticeably.
/// Hidden argv[1] that turns this binary into the key holder.
pub const HOLDER_ARG: &str = "__key-holder";

const BUSY: Duration = Duration::from_millis(50);

#[must_use]
pub fn debug_enabled() -> bool {
    std::env::var_os("NDO4GIT_DEBUG").is_some_and(|v| v == "1")
}

macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::exec::debug_enabled() {
            eprintln!("ndo4git: {}", format_args!($($arg)*));
        }
    };
}

fn is_executable_file(p: &Path) -> bool {
    fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Find the real `ssh`, skipping this very binary. `NDO4GIT_SSH` overrides.
#[must_use]
pub fn find_ssh() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("NDO4GIT_SSH").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let me = std::env::current_exe()
        .ok()
        .and_then(|p| fs::canonicalize(p).ok());
    let is_me = |cand: &Path| match (&me, fs::canonicalize(cand)) {
        (Some(me), Ok(c)) => *me == c,
        _ => false,
    };
    let path = std::env::var_os("PATH").unwrap_or_default();
    let from_path = std::env::split_paths(&path)
        .filter(|d| d.is_absolute()) // an empty / relative entry would mean "cwd": never trust it
        .map(|d| d.join("ssh"))
        .find(|c| is_executable_file(c) && !is_me(c));
    from_path.or_else(|| {
        ["/usr/bin/ssh", "/bin/ssh", "/usr/local/bin/ssh"]
            .iter()
            .map(PathBuf::from)
            .find(|c| is_executable_file(c) && !is_me(c))
    })
}

/// How unknown / changed server host keys are handled for managed calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostKeyPolicy {
    /// Trust a host key on first use, reject later changes (default).
    #[default]
    AcceptNew,
    /// Do not pass any option: ssh's own default (prompts; fails without a tty).
    Ask,
    /// Only hosts already in `known_hosts` are accepted.
    Strict,
}

impl HostKeyPolicy {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "accept-new" | "tofu" => Some(Self::AcceptNew),
            "ask" => Some(Self::Ask),
            "strict" | "yes" => Some(Self::Strict),
            _ => None,
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::AcceptNew => "accept-new",
            Self::Ask => "ask",
            Self::Strict => "strict",
        }
    }

    fn ssh_option(self) -> Option<&'static str> {
        match self {
            Self::AcceptNew => Some("StrictHostKeyChecking=accept-new"),
            Self::Ask => None,
            Self::Strict => Some("StrictHostKeyChecking=yes"),
        }
    }
}

/// The options we prepend for a managed call.
#[must_use]
pub fn managed_prefix(key_path: &str, policy: HostKeyPolicy) -> Vec<OsString> {
    let mut v: Vec<&str> = vec![
        "-i",
        key_path,
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
    ];
    if let Some(o) = policy.ssh_option() {
        v.extend(["-o", o]);
    }
    v.into_iter().map(OsString::from).collect()
}

/// Full argv (including argv[0] = `ssh`) for a managed call.
#[must_use]
pub fn managed_argv(key_path: &str, policy: HostKeyPolicy, original: &[OsString]) -> Vec<OsString> {
    let mut v = vec![OsString::from("ssh")];
    v.extend(managed_prefix(key_path, policy));
    v.extend(original.iter().cloned());
    v
}

/// A decrypted key together with the settings that apply to its host.
pub struct Lookup {
    pub pem: Zeroizing<Vec<u8>>,
    pub policy: HostKeyPolicy,
}

/// Look up and decrypt the key for this invocation. `Ok(None)` = not managed.
pub fn lookup_key(args: &[OsString]) -> Result<Option<Lookup>> {
    let sargs: Vec<&str> = args
        .iter()
        .map(|a| a.to_str())
        .collect::<Option<_>>()
        .ok_or_else(|| Error::Invalid("non-UTF-8 argument".into()))?;
    let inv = parse_ssh_args(&sargs).map_err(|e| Error::Invalid(e.to_string()))?;
    if inv.probe {
        return Ok(None);
    }
    let Some(cmd) = inv.command.as_deref() else {
        return Ok(None);
    };
    let repo = extract_repo_from_command(cmd).map_err(|e| Error::Invalid(e.to_string()))?;
    let host = inv.host.to_ascii_lowercase();

    let sudo = std::env::var_os("NDO4GIT_SUDO_USER_HOME").is_some_and(|v| v == "1");
    let dir = paths::config_dir(sudo)?;
    if !paths::db_path(&dir).exists() {
        debug!("no database at {}", dir.display());
        return Ok(None);
    }
    paths::check_perms(&dir, true)?;
    let db = Db::open(&paths::db_path(&dir), OpenMode::Existing, BUSY)?;
    if !host_is_configured(&host, &db.hosts()?) {
        debug!("{host} is not a managed host");
        return Ok(None);
    }
    let Some(secret) = db.resolve_secret(&repo, &host)? else {
        debug!("no key for {repo} on {host}");
        return Ok(None);
    };
    let master = MasterKey::load(&dir)?;
    let aad = record_aad(&secret.row.repo, &secret.row.host, &secret.row.algo);
    let pem = master.open(&aad, &secret.nonce, &secret.private_key_enc)?;
    if let Err(e) = db.touch(secret.row.id, now_unix()) {
        debug!("last_used_at update skipped: {e}");
    }
    debug!("using key {} for {repo} on {host}", secret.row.fingerprint);
    let policy = db.hostkey_policy()?;
    Ok(Some(Lookup { pem, policy }))
}

/// True when the key must be staged in a file rather than a `memfd`.
#[cfg(target_os = "linux")]
fn file_staging() -> bool {
    std::env::var_os("NDO4GIT_KEY_STAGING").is_some_and(|v| v == "file")
}

/// Per-user private directory (0700) for staged key files.
fn private_dir() -> Result<PathBuf> {
    let base = ["XDG_RUNTIME_DIR", "TMPDIR"]
        .iter()
        .filter_map(|n| std::env::var_os(n).filter(|v| !v.is_empty()))
        .map(PathBuf::from)
        .find(|p| p.is_absolute() && p.is_dir())
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    private_dir_in(&base)
}

fn private_dir_in(base: &Path) -> Result<PathBuf> {
    let uid = nix::unistd::geteuid().as_raw();
    let dir = base.join(format!("ndo4git-{uid}"));
    match fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).ctx(format!("creating {}", dir.display())),
    }
    let m = fs::symlink_metadata(&dir).ctx(format!("stat {}", dir.display()))?;
    if !m.is_dir() || m.uid() != uid || m.mode() & 0o077 != 0 {
        return Err(Error::Insecure(format!(
            "{} is not a private directory owned by you",
            dir.display()
        )));
    }
    Ok(dir)
}

/// Remove key files left behind by holders that were killed hard.
fn sweep_stale(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let stale = e.file_name().to_string_lossy().starts_with("key-")
            && e.metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|age| age > Duration::from_secs(24 * 3600));
        if stale {
            let _ = fs::remove_file(e.path());
        }
    }
}

/// Write the key to a fresh 0600 file in the private directory.
fn staged_file(pem: &[u8]) -> Result<PathBuf> {
    staged_file_in(&private_dir()?, pem)
}

fn staged_file_in(dir: &Path, pem: &[u8]) -> Result<PathBuf> {
    sweep_stale(dir);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let path = dir.join(format!("key-{}-{nanos}", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .ctx(format!("creating {}", path.display()))?;
    if let Err(e) = f.write_all(pem).and_then(|()| f.sync_all()) {
        let _ = fs::remove_file(&path);
        return Err(e).ctx("writing staged key");
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn fallback_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        v.push(PathBuf::from(d));
    }
    v.push(PathBuf::from("/dev/shm"));
    v.push(PathBuf::from("/tmp"));
    v
}

/// A 0600 file in a runtime directory, unlinked immediately (see module docs).
#[cfg(target_os = "linux")]
fn unlinked_tempfile(pem: &[u8]) -> Result<OwnedFd> {
    let mut last: Option<Error> = None;
    for dir in fallback_dirs() {
        let name = dir.join(format!(
            ".ndo4git-{}-{}",
            std::process::id(),
            now_unix().unsigned_abs() ^ u64::from(std::process::id()).rotate_left(17)
        ));
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&name)
        {
            Ok(mut f) => {
                let _ = fs::remove_file(&name);
                f.write_all(pem).ctx("writing temporary key")?;
                return Ok(OwnedFd::from(f));
            }
            Err(e) => {
                last = Some(Error::Io {
                    context: format!("creating {}", name.display()),
                    source: e,
                });
            }
        }
    }
    Err(last.unwrap_or_else(|| Error::Invalid("no usable runtime directory".into())))
}

/// Put `pem` into an anonymous in-memory file (Linux), falling back to an unlinked file.
#[cfg(target_os = "linux")]
fn key_fd(pem: &[u8]) -> Result<OwnedFd> {
    use std::fs::File;
    let name = CString::new("ndo4git-key").map_err(|e| Error::Invalid(e.to_string()))?;
    match memfd_create(&name, MemFdCreateFlag::empty()) {
        Ok(fd) => {
            let mut f = File::from(fd);
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .ctx("chmod memfd")?;
            f.write_all(pem).ctx("writing memfd")?;
            Ok(OwnedFd::from(f))
        }
        Err(e) => {
            debug!("memfd_create failed ({e}); using unlinked temp file");
            unlinked_tempfile(pem)
        }
    }
}

/// What the holder keeps alive for ssh to read.
enum Staged {
    #[cfg(target_os = "linux")]
    Fd(OwnedFd),
    File(PathBuf),
}

impl Staged {
    fn new(pem: &[u8]) -> Result<Self> {
        #[cfg(target_os = "linux")]
        if !file_staging() {
            return key_fd(pem).map(Self::Fd);
        }
        staged_file(pem).map(Self::File)
    }

    /// The path ssh must pass to `-i`.
    fn path(&self) -> String {
        match self {
            #[cfg(target_os = "linux")]
            Self::Fd(fd) => format!("/proc/{}/fd/{}", std::process::id(), fd.as_raw_fd()),
            Self::File(p) => p.display().to_string(),
        }
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        match self {
            Self::File(p) => {
                let _ = fs::remove_file(p);
            }
            #[cfg(target_os = "linux")]
            Self::Fd(_) => {}
        }
    }
}

fn to_cstring(s: &std::ffi::OsStr) -> Result<CString> {
    CString::new(s.as_bytes()).map_err(|e| Error::Invalid(e.to_string()))
}

/// `execv` the given program; only returns on failure.
fn exec_program(program: &Path, argv: &[OsString]) -> Error {
    let run = || -> Result<()> {
        let prog = to_cstring(program.as_os_str())?;
        let cargv: Vec<CString> = argv.iter().map(|a| to_cstring(a)).collect::<Result<_>>()?;
        nix::unistd::execv(&prog, &cargv)?;
        Ok(())
    };
    match run() {
        Ok(()) => Error::Invalid("exec returned unexpectedly".into()),
        Err(e) => e,
    }
}

/// Start the key holder and return the path ssh must read the key from.
fn spawn_holder(pem: &[u8]) -> Result<String> {
    let exe = std::env::current_exe().ctx("locating own executable")?;
    let mut cmd = Command::new(exe);
    cmd.arg(HOLDER_ARG)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0); // keep terminal signals away from the holder
    for name in ["XDG_RUNTIME_DIR", "TMPDIR", "NDO4GIT_KEY_STAGING"] {
        if let Some(d) = std::env::var_os(name) {
            cmd.env(name, d);
        }
    }
    let mut child = cmd.spawn().ctx("starting key holder")?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Invalid("holder stdin unavailable".into()))?;
        stdin.write_all(pem).ctx("sending key to holder")?;
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Invalid("holder stdout unavailable".into()))?;
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .ctx("reading holder reply")?;
    let path = line.trim();
    if !path.starts_with('/') {
        return Err(Error::Invalid(format!("bad holder reply {line:?}")));
    }
    // `child` is dropped without waiting: the holder outlives us (we exec) and
    // exits on its own when its parent, i.e. ssh, is gone.
    Ok(path.to_owned())
}

/// Entry point of `ndo4git __key-holder`: keep the key (from stdin) in an
/// in-memory file until the parent process exits.
#[must_use]
pub fn run_key_holder() -> i32 {
    let parent = nix::unistd::getppid();
    let mut pem = Zeroizing::new(Vec::new());
    if std::io::stdin().lock().read_to_end(&mut pem).is_err() {
        return 1;
    }
    let Ok(staged) = Staged::new(&pem) else {
        return 1;
    };
    drop(pem);
    // PDEATHSIG kills us without running destructors, so it is only used when
    // there is no file to clean up.
    #[cfg(target_os = "linux")]
    if matches!(staged, Staged::Fd(_)) {
        let _ = nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL);
    }
    {
        let mut out = std::io::stdout().lock();
        if writeln!(out, "{}", staged.path())
            .and_then(|()| out.flush())
            .is_err()
        {
            return 1;
        }
    }
    // Belt and braces next to PDEATHSIG (which can race with the parent's exit).
    while nix::unistd::getppid() == parent {
        std::thread::sleep(Duration::from_millis(250));
    }
    drop(staged);
    0
}

/// Entry point of `ndo4git ssh-wrapper`. `args` are the ssh arguments.
///
/// Returns only if `exec` of ssh itself failed; the value is the process exit code.
#[must_use]
pub fn run_wrapper(args: Vec<OsString>) -> i32 {
    let Some(ssh) = find_ssh() else {
        eprintln!("ndo4git: cannot find the real `ssh` in PATH (set NDO4GIT_SSH)");
        return 127;
    };
    match lookup_key(&args) {
        Ok(Some(found)) => match spawn_holder(&found.pem) {
            Ok(path) => {
                let policy = found.policy;
                drop(found); // zeroizes our copy of the plaintext before exec
                let e = exec_program(&ssh, &managed_argv(&path, policy, &args));
                debug!("exec with key failed: {e}; retrying without");
            }
            Err(e) => debug!("could not stage key: {e}; falling back to plain ssh"),
        },
        Ok(None) => {}
        Err(e) => debug!("{e}; falling back to plain ssh"),
    }
    let mut argv = vec![OsString::from("ssh")];
    argv.extend(args);
    let e = exec_program(&ssh, &argv);
    eprintln!("ndo4git: cannot exec {}: {e}", ssh.display());
    126
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use std::fs::File;
    #[cfg(target_os = "linux")]
    use std::io::Read;

    #[test]
    fn argv_shape() {
        let orig: Vec<OsString> = ["-p", "22", "git@github.com", "git-upload-pack 'o/r'"]
            .iter()
            .map(OsString::from)
            .collect();
        let got: Vec<String> = managed_argv("/proc/1234/fd/9", HostKeyPolicy::AcceptNew, &orig)
            .into_iter()
            .map(|s| s.into_string().unwrap())
            .collect();
        assert_eq!(
            got,
            [
                "ssh",
                "-i",
                "/proc/1234/fd/9",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "IdentityAgent=none",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-p",
                "22",
                "git@github.com",
                "git-upload-pack 'o/r'"
            ]
        );
    }

    #[test]
    fn policy_options() {
        let has = |p| {
            managed_prefix("/k", p)
                .iter()
                .any(|a| a.to_string_lossy().starts_with("StrictHostKeyChecking="))
        };
        assert!(has(HostKeyPolicy::AcceptNew));
        assert!(has(HostKeyPolicy::Strict));
        assert!(!has(HostKeyPolicy::Ask));
        assert_eq!(HostKeyPolicy::parse("YES"), Some(HostKeyPolicy::Strict));
        assert_eq!(HostKeyPolicy::parse("tofu"), Some(HostKeyPolicy::AcceptNew));
        assert!(HostKeyPolicy::parse("no").is_none());
        assert_eq!(HostKeyPolicy::default().name(), "accept-new");
    }

    #[test]
    fn staged_file_is_private_and_cleaned_up() {
        let t = tempfile::tempdir().unwrap();
        let dir = private_dir_in(t.path()).unwrap();
        let staged = Staged::File(staged_file_in(&dir, b"secret").unwrap());
        let p = PathBuf::from(staged.path());
        assert!(p.starts_with(t.path()));
        assert_eq!(fs::read(&p).unwrap(), b"secret");
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(p.parent().unwrap()).unwrap().mode() & 0o777,
            0o700
        );
        drop(staged);
        assert!(!p.exists());
    }

    #[test]
    fn private_dir_rejects_loose_modes() {
        let t = tempfile::tempdir().unwrap();
        let d = t
            .path()
            .join(format!("ndo4git-{}", nix::unistd::geteuid().as_raw()));
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_dir_in(t.path()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn key_fd_roundtrip_is_0600() {
        let fd = key_fd(b"hello key\n").unwrap();
        let raw = fd.as_raw_fd();
        // reopen through /proc exactly like ssh would
        let mut f = File::open(format!("/proc/self/fd/{raw}")).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello key\n");
        assert_eq!(f.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unlinked_fallback_works() {
        let fd = unlinked_tempfile(b"abc").unwrap();
        let mut s = String::new();
        File::open(format!("/proc/self/fd/{}", fd.as_raw_fd()))
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "abc");
    }

    #[test]
    fn lookup_ignores_unmanaged_shapes() {
        for a in [
            vec!["-G", "variant-test-host"],
            vec!["git@github.com"],
            vec!["git@github.com", "ls"],
            vec!["-Z", "git@github.com", "git-upload-pack 'o/r'"],
        ] {
            let args: Vec<OsString> = a.iter().map(OsString::from).collect();
            assert!(matches!(lookup_key(&args), Ok(None) | Err(_)));
            assert!(!matches!(lookup_key(&args), Ok(Some(_))));
        }
    }
}
