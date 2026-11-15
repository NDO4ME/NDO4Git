//! The `git` shim: a symlink named `git` that points at the ndo4git binary.
//!
//! When the binary is started as `git` it does nothing but locate the *real*
//! git (skipping itself) and `exec` it with the original arguments, so the
//! process is replaced: no proxying, no extra memory, same exit status and
//! stdio. SSH key selection itself is done by `core.sshCommand`, which also
//! covers tools that call `/usr/bin/git` directly.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Name the binary is installed under; a candidate that resolves to a file
/// with this name is never "the real git".
const OUR_NAME: &str = "ndo4git";

/// First executable `git` in `path` that is not ndo4git itself.
///
/// Relative and empty `PATH` entries are ignored (a relative entry would let
/// the current directory decide which program runs).
#[must_use]
pub fn find_real_git(path: &OsStr, self_exe: Option<&Path>) -> Option<PathBuf> {
    let me = self_exe
        .and_then(|p| fs::metadata(p).ok())
        .map(|m| (m.dev(), m.ino()));
    for dir in std::env::split_paths(path) {
        if !dir.is_absolute() {
            continue;
        }
        let cand = dir.join("git");
        let Ok(md) = fs::metadata(&cand) else {
            continue;
        };
        if !md.is_file() || md.permissions().mode() & 0o111 == 0 {
            continue;
        }
        if me == Some((md.dev(), md.ino())) {
            continue;
        }
        let ours = fs::canonicalize(&cand)
            .ok()
            .and_then(|c| c.file_name().map(|n| n == OUR_NAME))
            .unwrap_or(false);
        if ours {
            continue;
        }
        return Some(cand);
    }
    None
}

/// Where git lives when `PATH` is unset or only contains the shim (minimal
/// environments such as `env -i`, cron or an IDE). Without this fallback the
/// shim could break a call that works with the real git.
const FALLBACK_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/opt/homebrew/bin",
    "/usr/local/git/bin",
    "/Library/Developer/CommandLineTools/usr/bin",
];

/// [`find_real_git`] in `path`, then in [`FALLBACK_DIRS`].
#[must_use]
pub fn find_real_git_or_fallback(path: &OsStr, self_exe: Option<&Path>) -> Option<PathBuf> {
    find_real_git(path, self_exe).or_else(|| {
        let dirs = std::env::join_paths(FALLBACK_DIRS).ok()?;
        find_real_git(&dirs, self_exe)
    })
}

/// Number of nested shim executions, passed down in the environment. Two
/// ndo4git copies named `git` in front of each other would otherwise `exec`
/// one another forever.
const DEPTH_VAR: &str = "NDO4GIT_SHIM_DEPTH";
const MAX_DEPTH: u32 = 32;

/// True when `argv0` names the shim (`git`, `/usr/local/bin/git`).
#[must_use]
pub fn invoked_as_git(argv0: &OsStr) -> bool {
    Path::new(argv0).file_name() == Some(OsStr::new("git"))
}

/// Replace this process with the real git. Only returns on failure; the
/// value is the exit code to use (127: git not found, 126: cannot execute).
#[must_use]
pub fn exec_real_git(args: Vec<OsString>) -> i32 {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let exe = std::env::current_exe().ok();
    let depth = std::env::var(DEPTH_VAR)
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    if depth >= MAX_DEPTH {
        eprintln!("ndo4git: the git shim is calling itself (more than {MAX_DEPTH} levels); check PATH for stray copies named `git`");
        return 126;
    }
    let Some(real) = find_real_git_or_fallback(&path, exe.as_deref()) else {
        eprintln!("ndo4git: cannot find the real `git` in PATH; is git installed?");
        return 127;
    };
    let err = Command::new(&real)
        .args(args)
        .env(DEPTH_VAR, (depth + 1).to_string())
        .exec();
    eprintln!("ndo4git: cannot execute {}: {err}", real.display());
    126
}

/// Hint for installing git, based on the package manager present.
#[must_use]
pub fn install_hint() -> &'static str {
    const CANDIDATES: &[(&str, &str)] = &[
        ("/usr/bin/apt-get", "sudo apt install git"),
        ("/usr/bin/dnf", "sudo dnf install git"),
        ("/usr/bin/yum", "sudo yum install git"),
        ("/usr/bin/pacman", "sudo pacman -S git"),
        ("/sbin/apk", "sudo apk add git"),
        ("/usr/bin/zypper", "sudo zypper install git"),
        ("/opt/homebrew/bin/brew", "brew install git"),
        ("/usr/local/bin/brew", "brew install git"),
    ];
    CANDIDATES
        .iter()
        .find(|(p, _)| Path::new(p).exists())
        .map_or("install git with your package manager", |(_, h)| h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn script(p: &Path) {
        fs::write(p, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn skips_the_shim_and_finds_real_git() {
        let t = tempfile::tempdir().unwrap();
        let shim_dir = t.path().join("shim");
        let real_dir = t.path().join("real");
        fs::create_dir_all(&shim_dir).unwrap();
        fs::create_dir_all(&real_dir).unwrap();
        let bin = t.path().join("ndo4git");
        script(&bin);
        symlink(&bin, shim_dir.join("git")).unwrap();
        script(&real_dir.join("git"));
        let path = std::env::join_paths([&shim_dir, &real_dir]).unwrap();
        assert_eq!(find_real_git(&path, None), Some(real_dir.join("git")));
        // also when only the inode identifies us (copy-less hard link)
        let other = t.path().join("other");
        fs::create_dir_all(&other).unwrap();
        fs::hard_link(&bin, other.join("git")).unwrap();
        let path = std::env::join_paths([&other, &real_dir]).unwrap();
        assert_eq!(find_real_git(&path, Some(&bin)), Some(real_dir.join("git")));
    }

    #[test]
    fn none_when_only_the_shim_exists() {
        let t = tempfile::tempdir().unwrap();
        let bin = t.path().join("ndo4git");
        script(&bin);
        symlink(&bin, t.path().join("git")).unwrap();
        assert_eq!(find_real_git(t.path().as_os_str(), None), None);
    }

    #[test]
    fn ignores_relative_and_non_executable_entries() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("d");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("git"), b"x").unwrap(); // not executable
        let path = std::env::join_paths([Path::new("."), Path::new(""), d.as_path()]).unwrap();
        assert_eq!(find_real_git(&path, None), None);
    }

    #[test]
    fn fallback_finds_git_when_path_only_has_the_shim() {
        let t = tempfile::tempdir().unwrap();
        let bin = t.path().join("ndo4git");
        script(&bin);
        symlink(&bin, t.path().join("git")).unwrap();
        // PATH holds only the shim: strict search fails, the fallback finds the system git (if any)
        assert_eq!(find_real_git(t.path().as_os_str(), None), None);
        let sys = FALLBACK_DIRS
            .iter()
            .map(|d| Path::new(d).join("git"))
            .find(|p| p.is_file());
        assert_eq!(find_real_git_or_fallback(t.path().as_os_str(), None), sys);
    }

    #[test]
    fn argv0_detection() {
        assert!(invoked_as_git(OsStr::new("git")));
        assert!(invoked_as_git(OsStr::new("/usr/local/bin/git")));
        assert!(!invoked_as_git(OsStr::new("ndo4git")));
        assert!(!invoked_as_git(OsStr::new("git-ndo4git")));
    }
}
