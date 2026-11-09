//! System-wide install / uninstall (requires root).
//!
//! `install` copies the running binary to `<bin_dir>/ndo4git`, links
//! `git-ndo4git`, and points `core.sshCommand` in the *system* gitconfig at
//! the wrapper, remembering any previous value in `<state_dir>/previous_sshcommand`.

use crate::error::{Error, IoContext, Result};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const KEY: &str = "core.sshCommand";

#[derive(Debug, Clone)]
pub struct Plan {
    pub bin_dir: PathBuf,
    pub state_dir: PathBuf,
    pub source_exe: PathBuf,
    pub require_root: bool,
    /// Extra environment for the `git` subprocess (tests point `GIT_CONFIG_SYSTEM` at a temp file).
    pub git_env: Vec<(String, String)>,
    pub passwd_path: PathBuf,
}

impl Plan {
    /// The real, system-wide plan.
    pub fn system() -> Result<Self> {
        Ok(Self {
            bin_dir: PathBuf::from("/usr/local/bin"),
            state_dir: PathBuf::from("/etc/ndo4git"),
            source_exe: std::env::current_exe().ctx("locating the running executable")?,
            require_root: true,
            git_env: Vec::new(),
            passwd_path: PathBuf::from("/etc/passwd"),
        })
    }

    #[must_use]
    pub fn bin_path(&self) -> PathBuf {
        self.bin_dir.join("ndo4git")
    }

    #[must_use]
    pub fn link_path(&self) -> PathBuf {
        self.bin_dir.join("git-ndo4git")
    }

    #[must_use]
    pub fn previous_path(&self) -> PathBuf {
        self.state_dir.join("previous_sshcommand")
    }

    /// The value written to `core.sshCommand`.
    #[must_use]
    pub fn ssh_command(&self) -> String {
        format!("{} ssh-wrapper", self.bin_path().display())
    }

    fn check_root(&self) -> Result<()> {
        if self.require_root && !nix::unistd::geteuid().is_root() {
            return Err(Error::Invalid(
                "this command must be run as root (try: sudo ndo4git install)".into(),
            ));
        }
        Ok(())
    }

    fn git(&self, args: &[&str]) -> Result<std::process::Output> {
        let mut c = Command::new("git");
        c.args(args);
        for (k, v) in &self.git_env {
            c.env(k, v);
        }
        c.output().ctx("running git (is it installed?)")
    }

    /// Value of `core.sshCommand` in the given scope flag (`--system`, ...).
    pub fn config_get(&self, scope: &str) -> Result<Option<String>> {
        git_config_get(scope, &self.git_env)
    }

    fn config_set(&self, value: &str) -> Result<()> {
        let o = self.git(&["config", "--system", KEY, value])?;
        if o.status.success() {
            Ok(())
        } else {
            Err(Error::Invalid(format!(
                "git config --system failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            )))
        }
    }

    fn config_unset(&self) -> Result<()> {
        let o = self.git(&["config", "--system", "--unset-all", KEY])?;
        // exit 5 = key not present: fine
        if o.status.success() || o.status.code() == Some(5) {
            Ok(())
        } else {
            Err(Error::Invalid(format!(
                "git config --system --unset-all failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            )))
        }
    }

    /// Install (idempotent). Returns log lines describing what was done.
    pub fn install(&self) -> Result<Vec<String>> {
        self.check_root()?;
        let mut log = Vec::new();
        fs::create_dir_all(&self.bin_dir).ctx(format!("creating {}", self.bin_dir.display()))?;

        if atomic_copy(&self.source_exe, &self.bin_path())? {
            log.push(format!("installed {}", self.bin_path().display()));
        } else {
            log.push(format!("{} already up to date", self.bin_path().display()));
        }
        if atomic_symlink("ndo4git", &self.link_path())? {
            log.push(format!("linked {} -> ndo4git", self.link_path().display()));
        }

        let ours = self.ssh_command();
        let current = self.config_get("--system")?;
        fs::create_dir_all(&self.state_dir)
            .ctx(format!("creating {}", self.state_dir.display()))?;
        match current {
            Some(v) if v == ours => log.push("system core.sshCommand already set".into()),
            Some(prev) => {
                write_atomic(&self.previous_path(), prev.as_bytes(), 0o644)?;
                log.push(format!(
                    "saved previous core.sshCommand ({prev:?}) to {}",
                    self.previous_path().display()
                ));
                self.config_set(&ours)?;
                log.push(format!("set system core.sshCommand = {ours:?}"));
            }
            None => {
                let _ = fs::remove_file(self.previous_path()); // stale from an older install
                self.config_set(&ours)?;
                log.push(format!("set system core.sshCommand = {ours:?}"));
            }
        }
        Ok(log)
    }

    /// Reverse [`Plan::install`]. With `purge`, also delete every user's
    /// `~/.config/ndo4git` found in the passwd database.
    pub fn uninstall(&self, purge: bool) -> Result<Vec<String>> {
        self.check_root()?;
        let mut log = Vec::new();
        let ours = self.ssh_command();
        match self.config_get("--system")? {
            Some(v) if v == ours => {
                if let Ok(prev) = fs::read_to_string(self.previous_path()) {
                    self.config_set(&prev)?;
                    log.push(format!("restored system core.sshCommand = {prev:?}"));
                } else {
                    self.config_unset()?;
                    log.push("removed system core.sshCommand".into());
                }
            }
            Some(other) => log.push(format!(
                "system core.sshCommand is {other:?} (not ours); left untouched"
            )),
            None => log.push("system core.sshCommand not set".into()),
        }
        for p in [self.link_path(), self.bin_path(), self.previous_path()] {
            if fs::symlink_metadata(&p).is_ok() {
                fs::remove_file(&p).ctx(format!("removing {}", p.display()))?;
                log.push(format!("removed {}", p.display()));
            }
        }
        if fs::remove_dir(&self.state_dir).is_ok() {
            log.push(format!("removed {}", self.state_dir.display()));
        }
        if purge {
            for d in self.user_data_dirs()? {
                fs::remove_dir_all(&d).ctx(format!("purging {}", d.display()))?;
                log.push(format!("purged {}", d.display()));
            }
        } else {
            log.push(
                "user data (~/.config/ndo4git) left untouched; use --purge to delete it".into(),
            );
        }
        Ok(log)
    }

    /// `<home>/.config/ndo4git` for every passwd entry where it exists as a real directory.
    pub fn user_data_dirs(&self) -> Result<Vec<PathBuf>> {
        let text = fs::read_to_string(&self.passwd_path)
            .ctx(format!("reading {}", self.passwd_path.display()))?;
        let mut out: Vec<PathBuf> = Vec::new();
        for line in text.lines() {
            let home = line.split(':').nth(5).unwrap_or("");
            if !home.starts_with('/') || home == "/" {
                continue;
            }
            let d = Path::new(home).join(".config").join("ndo4git");
            let is_real_dir = fs::symlink_metadata(&d).is_ok_and(|m| m.is_dir());
            if is_real_dir && !out.contains(&d) {
                out.push(d);
            }
        }
        Ok(out)
    }
}

/// `git config <scope> --get core.sshCommand`. `Ok(None)` when unset.
pub fn git_config_get(scope: &str, env: &[(String, String)]) -> Result<Option<String>> {
    let mut c = Command::new("git");
    c.args(["config", scope, "--get", KEY]);
    for (k, v) in env {
        c.env(k, v);
    }
    let o = c.output().ctx("running git (is it installed?)")?;
    match o.status.code() {
        Some(0) => {
            let s = String::from_utf8_lossy(&o.stdout);
            Ok(Some(s.strip_suffix('\n').unwrap_or(&s).to_owned()))
        }
        Some(1) => Ok(None),
        _ => Err(Error::Invalid(format!(
            "git config {scope} failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        ))),
    }
}

fn tmp_name(dst: &Path) -> PathBuf {
    let base = dst.file_name().map(OsString::from).unwrap_or_default();
    let mut n = OsString::from(".");
    n.push(base);
    n.push(format!(".tmp.{}", std::process::id()));
    dst.with_file_name(n)
}

/// Write `data` to `dst` atomically (temp file + rename).
pub fn write_atomic(dst: &Path, data: &[u8], mode: u32) -> Result<()> {
    let tmp = tmp_name(dst);
    let _ = fs::remove_file(&tmp);
    let res = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, dst)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.ctx(format!("writing {}", dst.display()))
}

/// Copy `src` to `dst` (0755) atomically. Returns false if nothing needed doing
/// (`src` and `dst` are already the same file).
fn atomic_copy(src: &Path, dst: &Path) -> Result<bool> {
    if let (Ok(a), Ok(b)) = (fs::canonicalize(src), fs::canonicalize(dst)) {
        if a == b {
            return Ok(false);
        }
    }
    let tmp = tmp_name(dst);
    let _ = fs::remove_file(&tmp);
    let res = (|| -> std::io::Result<()> {
        fs::copy(src, &tmp)?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))?;
        fs::File::open(&tmp)?.sync_all()?;
        fs::rename(&tmp, dst)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.ctx(format!("installing {}", dst.display()))?;
    Ok(true)
}

/// Point symlink `link` at `target` atomically. Returns false if already correct.
fn atomic_symlink(target: &str, link: &Path) -> Result<bool> {
    if fs::read_link(link).is_ok_and(|t| t == Path::new(target)) {
        return Ok(false);
    }
    let tmp = tmp_name(link);
    let _ = fs::remove_file(&tmp);
    let res = symlink(target, &tmp).and_then(|()| fs::rename(&tmp, link));
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.ctx(format!("linking {}", link.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(t: &Path) -> Plan {
        // a fake "binary" to install
        let src = t.join("src-bin");
        fs::write(&src, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::write(
            t.join("passwd"),
            format!(
                "alice:x:1000:1000::{}:/bin/sh\nroot:x:0:0::/nonexistent:/bin/sh\n",
                t.join("home/alice").display()
            ),
        )
        .unwrap();
        Plan {
            bin_dir: t.join("bin"),
            state_dir: t.join("etc/ndo4git"),
            source_exe: src,
            require_root: false,
            git_env: vec![
                (
                    "GIT_CONFIG_SYSTEM".into(),
                    t.join("gitconfig").display().to_string(),
                ),
                ("GIT_CONFIG_NOSYSTEM".into(), "0".into()),
            ],
            passwd_path: t.join("passwd"),
        }
    }

    #[test]
    fn install_is_idempotent_and_uninstall_restores_previous() {
        let t = tempfile::tempdir().unwrap();
        let p = plan(t.path());
        fs::write(
            t.path().join("gitconfig"),
            "[core]\n\tsshCommand = ssh -F /etc/custom\n",
        )
        .unwrap();

        p.install().unwrap();
        let again = p.install().unwrap();
        assert!(again.iter().any(|l| l.contains("already set")), "{again:?}");
        assert_eq!(p.config_get("--system").unwrap().unwrap(), p.ssh_command());
        assert_eq!(
            fs::read_to_string(p.previous_path()).unwrap(),
            "ssh -F /etc/custom"
        );
        assert_eq!(
            fs::metadata(p.bin_path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(fs::read_link(p.link_path()).unwrap(), Path::new("ndo4git"));
        // no temp litter
        assert_eq!(fs::read_dir(&p.bin_dir).unwrap().count(), 2);

        p.uninstall(false).unwrap();
        assert_eq!(
            p.config_get("--system").unwrap().unwrap(),
            "ssh -F /etc/custom"
        );
        assert!(!p.bin_path().exists());
        assert!(fs::symlink_metadata(p.link_path()).is_err());
        assert!(!p.state_dir.exists());
    }

    #[test]
    fn uninstall_unsets_when_nothing_was_there() {
        let t = tempfile::tempdir().unwrap();
        let p = plan(t.path());
        p.install().unwrap();
        assert!(!p.previous_path().exists());
        p.uninstall(false).unwrap();
        assert_eq!(p.config_get("--system").unwrap(), None);
    }

    #[test]
    fn uninstall_leaves_foreign_value_alone() {
        let t = tempfile::tempdir().unwrap();
        let p = plan(t.path());
        p.install().unwrap();
        p.config_set("something else").unwrap();
        p.uninstall(false).unwrap();
        assert_eq!(p.config_get("--system").unwrap().unwrap(), "something else");
    }

    #[test]
    fn purge_only_with_flag() {
        let t = tempfile::tempdir().unwrap();
        let p = plan(t.path());
        let data = t.path().join("home/alice/.config/ndo4git");
        fs::create_dir_all(&data).unwrap();
        fs::write(data.join("keys.db"), b"x").unwrap();
        p.install().unwrap();
        p.uninstall(false).unwrap();
        assert!(data.exists());
        p.install().unwrap();
        let log = p.uninstall(true).unwrap();
        assert!(!data.exists(), "{log:?}");
    }

    #[test]
    fn refuses_without_root() {
        let t = tempfile::tempdir().unwrap();
        let mut p = plan(t.path());
        p.require_root = true;
        if !nix::unistd::geteuid().is_root() {
            let e = p.install().unwrap_err().to_string();
            assert!(e.contains("must be run as root"), "{e}");
            assert!(p.uninstall(false).is_err());
        }
    }
}
