//! Locating and securing the per-user data directory.

use crate::error::{Error, IoContext, Result};
use nix::fcntl::OFlag;
use nix::unistd::{geteuid, User};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const DB_FILE: &str = "keys.db";
pub const MASTER_KEY_FILE: &str = "master.key";
const FILES: [&str; 4] = [DB_FILE, "keys.db-wal", "keys.db-shm", MASTER_KEY_FILE];

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Resolve `~/.config/ndo4git` (or `$XDG_CONFIG_HOME/ndo4git`).
///
/// The home directory comes from the passwd entry of the *effective* uid, not
/// from `$HOME` (which `sudo` may leave pointing at another user). `$HOME` is
/// only a fallback for containers with no passwd entry. When
/// `sudo_user_home` is set and we run as root, `$SUDO_USER`'s home is used.
pub fn config_dir(sudo_user_home: bool) -> Result<PathBuf> {
    let euid = geteuid();
    if sudo_user_home && euid.is_root() {
        let name = nonempty_env("SUDO_USER")
            .ok_or_else(|| Error::Invalid("--sudo-user-home requires $SUDO_USER".into()))?;
        let user = User::from_name(&name)?
            .ok_or_else(|| Error::Invalid(format!("unknown SUDO_USER {name:?}")))?;
        return Ok(user.dir.join(".config").join("ndo4git"));
    }
    if let Some(x) = nonempty_env("XDG_CONFIG_HOME") {
        let p = PathBuf::from(x);
        if p.is_absolute() {
            return Ok(p.join("ndo4git"));
        }
    }
    let home = match User::from_uid(euid) {
        Ok(Some(u)) if !u.dir.as_os_str().is_empty() => u.dir,
        _ => nonempty_env("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or(Error::NoHome)?,
    };
    Ok(home.join(".config").join("ndo4git"))
}

#[must_use]
pub fn db_path(dir: &Path) -> PathBuf {
    dir.join(DB_FILE)
}

/// Create the data directory (0700) if missing.
pub fn create_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent).ctx(format!("creating {}", parent.display()))?;
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e).ctx(format!("creating {}", dir.display())),
    }
}

/// Inspect the data directory and its files. With `fix`, repair loose modes.
/// Returns human-readable descriptions of every problem found.
///
/// Ownership problems and a non-directory are never auto-fixed: they are
/// returned as an `Err`.
pub fn check_perms(dir: &Path, fix: bool) -> Result<Vec<String>> {
    let euid = geteuid().as_raw();
    let meta = fs::metadata(dir).ctx(format!("stat {}", dir.display()))?;
    if !meta.is_dir() {
        return Err(Error::Insecure(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    if meta.uid() != euid {
        return Err(Error::Insecure(format!(
            "{} is owned by uid {}, expected {euid}",
            dir.display(),
            meta.uid()
        )));
    }
    let mut problems = Vec::new();
    if meta.mode() & 0o077 != 0 {
        problems.push(format!(
            "{} has mode {:o}, want 700",
            dir.display(),
            meta.mode() & 0o7777
        ));
        if fix {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
                .ctx(format!("chmod {}", dir.display()))?;
        }
    }
    for name in FILES {
        let p = dir.join(name);
        let Ok(m) = fs::symlink_metadata(&p) else {
            continue;
        };
        if m.file_type().is_symlink() {
            return Err(Error::Insecure(format!(
                "{} is a symlink; refusing",
                p.display()
            )));
        }
        if m.uid() != euid {
            return Err(Error::Insecure(format!(
                "{} is not owned by the current user",
                p.display()
            )));
        }
        if m.mode() & 0o077 != 0 {
            problems.push(format!(
                "{} has mode {:o}, want 600",
                p.display(),
                m.mode() & 0o7777
            ));
            if fix {
                fs::set_permissions(&p, fs::Permissions::from_mode(0o600))
                    .ctx(format!("chmod {}", p.display()))?;
            }
        }
    }
    Ok(problems)
}

/// Create the directory if needed and fix permissions. Used by every
/// command except the hot-path wrapper (which never creates anything).
pub fn ensure_dir(dir: &Path) -> Result<()> {
    create_dir(dir)?;
    check_perms(dir, true).map(|_| ())
}

/// `O_NOFOLLOW` as a raw custom-flags value for `OpenOptionsExt`.
#[must_use]
pub fn o_nofollow() -> i32 {
    OFlag::O_NOFOLLOW.bits()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixes_loose_modes() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("ndo4git");
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(d.join(MASTER_KEY_FILE), b"x").unwrap();
        fs::set_permissions(d.join(MASTER_KEY_FILE), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(check_perms(&d, false).unwrap().len(), 2);
        assert_eq!(check_perms(&d, true).unwrap().len(), 2);
        assert!(check_perms(&d, false).unwrap().is_empty());
        assert_eq!(fs::metadata(&d).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn ensure_dir_creates_0700() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path().join("a/b/ndo4git");
        ensure_dir(&d).unwrap();
        assert_eq!(fs::metadata(&d).unwrap().mode() & 0o777, 0o700);
    }
}
