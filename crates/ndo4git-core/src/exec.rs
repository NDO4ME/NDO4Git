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

use crate::crypto::{record_aad, MasterKey};
use crate::db::{Db, OpenMode};
use crate::error::{Error, IoContext, Result};
use crate::paths;
use crate::util::now_unix;
use crate::wrapper::{extract_repo_from_command, host_is_configured, parse_ssh_args};
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use std::ffi::{CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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

/// The options we prepend for a managed call.
#[must_use]
pub fn managed_prefix(key_path: &str) -> Vec<OsString> {
    [
        "-i",
        key_path,
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    .iter()
    .map(OsString::from)
    .collect()
}

/// Full argv (including argv[0] = `ssh`) for a managed call.
#[must_use]
pub fn managed_argv(key_path: &str, original: &[OsString]) -> Vec<OsString> {
    let mut v = vec![OsString::from("ssh")];
    v.extend(managed_prefix(key_path));
    v.extend(original.iter().cloned());
    v
}

/// Look up and decrypt the key for this invocation. `Ok(None)` = not managed.
pub fn lookup_key(args: &[OsString]) -> Result<Option<Zeroizing<Vec<u8>>>> {
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
    Ok(Some(pem))
}

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

/// Put `pem` into a descriptor that will survive `exec`.
pub fn key_fd(pem: &[u8]) -> Result<OwnedFd> {
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
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        cmd.env("XDG_RUNTIME_DIR", d);
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
    let fd: u32 = line
        .trim()
        .parse()
        .map_err(|_| Error::Invalid(format!("bad holder reply {line:?}")))?;
    // `child` is dropped without waiting: the holder outlives us (we exec) and
    // exits on its own when its parent, i.e. ssh, is gone.
    Ok(format!("/proc/{}/fd/{fd}", child.id()))
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
    let Ok(fd) = key_fd(&pem) else {
        return 1;
    };
    drop(pem);
    let _ = nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL);
    {
        let mut out = std::io::stdout().lock();
        if writeln!(out, "{}", fd.as_raw_fd())
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
        Ok(Some(pem)) => match spawn_holder(&pem) {
            Ok(path) => {
                drop(pem); // zeroizes our copy of the plaintext before exec
                let e = exec_program(&ssh, &managed_argv(&path, &args));
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
    use std::io::Read;

    #[test]
    fn argv_shape() {
        let orig: Vec<OsString> = ["-p", "22", "git@github.com", "git-upload-pack 'o/r'"]
            .iter()
            .map(OsString::from)
            .collect();
        let got: Vec<String> = managed_argv("/proc/1234/fd/9", &orig)
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
