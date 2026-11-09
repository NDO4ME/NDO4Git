//! End-to-end tests: real `ndo4git` binary, temp config dir, fake `ssh` on PATH.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::assert_is_empty,
    clippy::items_after_statements
)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_ndo4git");

struct Env {
    cfg: TempDir,
    fakebin: TempDir,
    log: PathBuf,
}

impl Env {
    fn new() -> Self {
        let cfg = tempfile::tempdir().unwrap();
        let fakebin = tempfile::tempdir().unwrap();
        let log = cfg.path().join("ssh.log");
        let script = fakebin.path().join("ssh");
        // Records argv (tab separated) and the content of the -i file.
        fs::write(
            &script,
            r#"#!/bin/sh
PATH=/usr/bin:/bin
{ printf 'ARGV'; for a in "$@"; do printf '\t%s' "$a"; done; printf '\n'; } >> "$FAKE_LOG"
prev=""
for a in "$@"; do
  if [ "$prev" = "-i" ]; then cat "$a" >> "$FAKE_LOG.key"; echo "-----END-CAPTURE-----" >> "$FAKE_LOG.key"; fi
  prev="$a"
done
prev=""
for a in "$@"; do
  if [ "$prev" = "-i" ]; then printf 'KEYLINE\t%s\n' "$(cat "$a" | head -n1)" >> "$FAKE_LOG.keyline"; fi
  prev="$a"
done
exit "${FAKE_SSH_EXIT:-0}"
"#,
        )
        .unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        Self { cfg, fakebin, log }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(BIN);
        c.env_clear()
            .env("PATH", self.fakebin.path())
            .env("XDG_CONFIG_HOME", self.cfg.path().join("xdg"))
            .env("FAKE_LOG", &self.log)
            .env("NDO4GIT_BACKUP_PASSPHRASE", "test-pass");
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let o = self.run(args);
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        String::from_utf8(o.stdout).unwrap()
    }

    fn wrapper(&self, ssh_args: &[&str]) -> Output {
        self.cmd()
            .arg("ssh-wrapper")
            .args(ssh_args)
            .output()
            .unwrap()
    }

    fn argv_lines(&self) -> Vec<Vec<String>> {
        fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|l| l.split('\t').skip(1).map(str::to_owned).collect())
            .collect()
    }

    fn clear_log(&self) {
        let _ = fs::remove_file(&self.log);
        let _ = fs::remove_file(format!("{}.key", self.log.display()));
    }

    fn captured_keys(&self) -> Vec<String> {
        fs::read_to_string(format!("{}.key", self.log.display()))
            .unwrap_or_default()
            .split("-----END-CAPTURE-----\n")
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }
}

const MANAGED_OPTS: [&str; 6] = [
    "-o",
    "IdentitiesOnly=yes",
    "-o",
    "IdentityAgent=none",
    "-o",
    "StrictHostKeyChecking=accept-new",
];

/// Assert `got` is `-i /proc/self/fd/N <managed opts> <orig>`.
fn assert_managed(got: &[String], orig: &[&str]) {
    assert_eq!(got[0], "-i", "{got:?}");
    assert!(
        got[1].starts_with("/proc/") && got[1].contains("/fd/"),
        "{got:?}"
    );
    assert_eq!(&got[2..8], MANAGED_OPTS, "{got:?}");
    assert_eq!(&got[8..], orig, "{got:?}");
}

fn s(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn managed_call_gets_exact_argv_and_a_valid_key() {
    let e = Env::new();
    e.ok(&["new", "Acme/Widget"]);
    let orig = [
        "-o",
        "SendEnv=GIT_PROTOCOL",
        "git@github.com",
        "git-upload-pack 'Acme/Widget.git'",
    ];
    let o = e.wrapper(&orig);
    assert!(o.status.success(), "{}", s(&o));
    let lines = e.argv_lines();
    assert_eq!(lines.len(), 1);
    assert_managed(&lines[0], &orig);
    let keys = e.captured_keys();
    assert_eq!(keys.len(), 1);
    assert!(keys[0].starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    // identical to what export-private prints
    assert_eq!(keys[0], e.ok(&["export-private", "acme/widget", "--yes"]));
    assert!(
        s(&o).is_empty(),
        "no stderr noise without NDO4GIT_DEBUG: {}",
        s(&o)
    );
}

#[test]
fn quoting_case_and_path_variants_all_match() {
    let e = Env::new();
    e.ok(&["new", "org/repo"]);
    for cmd in [
        "git-upload-pack 'org/repo.git'",
        "git-upload-pack '/org/repo.git'",
        "git-upload-pack org/repo",
        "git-receive-pack \"ORG/Repo.GIT\"",
        "git-upload-archive 'org/repo'",
        "git-lfs-authenticate 'org/repo.git' download",
    ] {
        e.clear_log();
        let o = e.wrapper(&["git@github.com", cmd]);
        assert!(o.status.success());
        let l = e.argv_lines();
        assert_managed(&l[0], &["git@github.com", cmd]);
    }
}

#[test]
fn ports_and_ssh_url_destination() {
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    for orig in [
        vec!["-p", "22", "git@github.com", "git-upload-pack 'o/r'"],
        vec!["-p22", "git@github.com", "git-upload-pack 'o/r'"],
        vec![
            "-4",
            "-T",
            "-oPort=22",
            "git@github.com",
            "git-upload-pack 'o/r'",
        ],
        vec!["ssh://git@github.com:22/", "git-upload-pack 'o/r'"],
    ] {
        e.clear_log();
        assert!(e.wrapper(&orig).status.success());
        assert_managed(&e.argv_lines()[0], &orig);
    }
}

#[test]
fn unmanaged_calls_are_passed_through_untouched() {
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    let cases: Vec<Vec<&str>> = vec![
        // no key for this repo
        vec!["git@github.com", "git-upload-pack 'o/other'"],
        // host not managed
        vec!["git@bitbucket.org", "git-upload-pack 'o/r'"],
        // git's ssh-variant probe
        vec!["-G", "variant-test-host"],
        // interactive shell / non-git command
        vec!["git@github.com"],
        vec!["git@github.com", "ls -la"],
        // malformed commands
        vec!["git@github.com", "git-upload-pack 'o/r"],
        vec!["git@github.com", "git-upload-pack"],
        vec!["git@github.com", "git-upload-pack '../../etc/passwd'"],
        vec!["git@github.com", "git-upload-pack 'o/r' extra"],
        // malformed ssh options
        vec!["-p", "notaport", "git@github.com", "git-upload-pack 'o/r'"],
        vec!["-Z", "git@github.com", "git-upload-pack 'o/r'"],
        vec!["-p"],
        vec![],
    ];
    for orig in cases {
        e.clear_log();
        let o = e.wrapper(&orig);
        assert!(o.status.success(), "{orig:?}: {}", s(&o));
        assert_eq!(
            e.argv_lines(),
            vec![orig.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>()],
            "{orig:?}"
        );
        assert!(e.captured_keys().is_empty());
    }
}

#[test]
fn exit_status_passes_through() {
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    for args in [
        vec!["git@github.com", "git-upload-pack 'o/r'"],
        vec!["git@github.com", "git-upload-pack 'x/y'"],
    ] {
        let o = e
            .cmd()
            .env("FAKE_SSH_EXIT", "7")
            .arg("ssh-wrapper")
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(7));
    }
}

#[test]
fn fails_open_on_every_internal_error() {
    let args = ["git@github.com", "git-upload-pack 'o/r'"];
    let plain = vec![args.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>()];

    // 1. nothing configured at all
    let e = Env::new();
    assert!(e.wrapper(&args).status.success());
    assert_eq!(e.argv_lines(), plain);

    // 2. corrupt database
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    let db = e.cfg.path().join("xdg/ndo4git/keys.db");
    fs::write(&db, b"this is not sqlite").unwrap();
    let _ = fs::remove_file(db.with_extension("db-wal"));
    let _ = fs::remove_file(db.with_extension("db-shm"));
    e.clear_log();
    let o = e.wrapper(&args);
    assert!(o.status.success());
    assert_eq!(e.argv_lines(), plain);
    assert!(s(&o).is_empty(), "silent without debug: {}", s(&o));
    e.clear_log();
    let o = e
        .cmd()
        .env("NDO4GIT_DEBUG", "1")
        .arg("ssh-wrapper")
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success());
    assert_eq!(e.argv_lines(), plain);
    assert!(
        s(&o).contains("ndo4git:"),
        "debug output expected: {}",
        s(&o)
    );

    // 3. master key lost
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    fs::remove_file(e.cfg.path().join("xdg/ndo4git/master.key")).unwrap();
    e.clear_log();
    assert!(e.wrapper(&args).status.success());
    assert_eq!(e.argv_lines(), plain);

    // 4. wrong master key (decryption failure)
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    fs::write(e.cfg.path().join("xdg/ndo4git/master.key"), [9u8; 32]).unwrap();
    e.clear_log();
    assert!(e.wrapper(&args).status.success());
    assert_eq!(e.argv_lines(), plain);
}

#[test]
fn missing_ssh_is_reported() {
    let e = Env::new();
    let o = e
        .cmd()
        .env("PATH", "/nonexistent-dir")
        .env("NDO4GIT_SSH", "/nonexistent/ssh")
        .arg("ssh-wrapper")
        .args(["h", "c"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(126));
}

#[test]
fn ssh_override_and_self_skipping() {
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    let args = ["git@github.com", "git-upload-pack 'o/r'"];

    // NDO4GIT_SSH wins even if PATH has nothing
    let alt = e.cfg.path().join("alt-ssh");
    fs::copy(e.fakebin.path().join("ssh"), &alt).unwrap();
    fs::set_permissions(&alt, fs::Permissions::from_mode(0o755)).unwrap();
    let o = e
        .cmd()
        .env("PATH", "/nonexistent")
        .env("NDO4GIT_SSH", &alt)
        .arg("ssh-wrapper")
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success());
    assert_managed(&e.argv_lines()[0], &args);

    // a PATH entry that is the wrapper itself (named ssh) must be skipped
    let selfdir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(BIN, selfdir.path().join("ssh")).unwrap();
    e.clear_log();
    let path = format!(
        "{}:{}",
        selfdir.path().display(),
        e.fakebin.path().display()
    );
    let o = e
        .cmd()
        .env("PATH", path)
        .arg("ssh-wrapper")
        .args(args)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", s(&o));
    assert_managed(&e.argv_lines()[0], &args);
}

#[test]
fn separate_keys_per_repo_like_submodules() {
    let e = Env::new();
    e.ok(&["new", "o/main"]);
    e.ok(&["new", "o/sub"]);
    for r in ["o/main", "o/sub", "o/main"] {
        assert!(e
            .wrapper(&["git@github.com", &format!("git-upload-pack '{r}.git'")])
            .status
            .success());
    }
    let keys = e.captured_keys();
    assert_eq!(keys.len(), 3);
    assert_eq!(keys[0], keys[2]);
    assert_ne!(keys[0], keys[1]);
}

#[test]
fn enterprise_hosts_and_aliases() {
    let e = Env::new();
    e.ok(&["new", "ghe.corp.example/o/r"]);
    let args = [
        "-p",
        "2222",
        "git@ghe.corp.example",
        "git-upload-pack 'o/r'",
    ];
    // not managed until the host is added
    e.clear_log();
    assert!(e.wrapper(&args).status.success());
    assert_eq!(e.argv_lines()[0], args);
    e.ok(&["host", "add", "GHE.corp.example"]);
    e.clear_log();
    assert!(e.wrapper(&args).status.success());
    assert_managed(&e.argv_lines()[0], &args);
    // key is per host: github.com/o/r has none
    e.clear_log();
    assert!(e
        .wrapper(&["git@github.com", "git-upload-pack 'o/r'"])
        .status
        .success());
    assert_eq!(
        e.argv_lines()[0],
        ["git@github.com", "git-upload-pack 'o/r'"]
    );

    // alias after a rename
    e.ok(&["new", "o/new-name"]);
    e.ok(&["alias", "o/old-name", "o/new-name"]);
    e.clear_log();
    assert!(e
        .wrapper(&["git@github.com", "git-upload-pack 'o/old-name.git'"])
        .status
        .success());
    assert_managed(
        &e.argv_lines()[0],
        &["git@github.com", "git-upload-pack 'o/old-name.git'"],
    );
    assert_ne!(
        e.run(&["alias", "o/missing", "o/nonexistent"])
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn last_used_is_updated() {
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    let before: serde_json::Value = serde_json::from_str(&e.ok(&["list", "--json"])).unwrap();
    assert!(before[0]["last_used_at"].is_null());
    assert!(e
        .wrapper(&["git@github.com", "git-upload-pack 'o/r'"])
        .status
        .success());
    let after: serde_json::Value = serde_json::from_str(&e.ok(&["list", "--json"])).unwrap();
    assert!(after[0]["last_used_at"].is_i64());
}

#[test]
fn concurrent_wrappers_all_succeed() {
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    let handles: Vec<_> = (0..12)
        .map(|_| {
            let mut c = e.cmd();
            c.arg("ssh-wrapper")
                .args(["git@github.com", "git-upload-pack 'o/r'"]);
            std::thread::spawn(move || c.output().unwrap())
        })
        .collect();
    for h in handles {
        assert!(h.join().unwrap().status.success());
    }
    let lines = fs::read_to_string(format!("{}.keyline", e.log.display())).unwrap();
    assert_eq!(lines.lines().count(), 12);
    assert!(
        lines
            .lines()
            .all(|l| l == "KEYLINE\t-----BEGIN OPENSSH PRIVATE KEY-----"),
        "{lines}"
    );
}

#[test]
fn real_git_drives_the_wrapper() {
    let e = Env::new();
    e.ok(&["new", "acme/widget"]);
    let work = tempfile::tempdir().unwrap();
    let helper = format!("{BIN} ssh-wrapper");
    let o = Command::new("git")
        .current_dir(work.path())
        .env_clear()
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", e.fakebin.path().display()),
        )
        .env("HOME", work.path())
        .env("XDG_CONFIG_HOME", e.cfg.path().join("xdg"))
        .env("FAKE_LOG", &e.log)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            &format!("core.sshCommand={helper}"),
            "ls-remote",
            "git@github.com:Acme/Widget.git",
        ])
        .output()
        .unwrap();
    // fake ssh produces no pack data, so git itself fails — we only care what ssh saw
    assert!(!o.status.success());
    let lines = e.argv_lines();
    let managed: Vec<_> = lines
        .iter()
        .filter(|l| l.first().is_some_and(|f| f == "-i"))
        .collect();
    assert_eq!(managed.len(), 1, "{lines:?}");
    let m = managed[0];
    assert!(m.contains(&"git@github.com".to_owned()), "{m:?}");
    assert!(m.last().unwrap().starts_with("git-upload-pack"), "{m:?}");
    // git's variant probe (`ssh -G`) must have reached ssh unmodified
    assert!(
        lines.iter().any(|l| l.first().is_some_and(|f| f == "-G")),
        "{lines:?}"
    );
}

// ---------------------------------------------------------------- management commands

#[test]
fn new_output_format_and_exit_codes() {
    let e = Env::new();
    let out = e.ok(&["new", "Foo/Bar", "--write", "--comment", "hello"]);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 7, "{out}");
    assert_eq!(lines[0], "Repo:        foo/bar");
    assert!(lines[1].starts_with("Fingerprint: SHA256:"));
    assert_eq!(lines[2], "Add this public key at:");
    assert_eq!(lines[3], "https://github.com/foo/bar/settings/keys/new");
    assert_eq!(lines[4], "(Allow write access: yes)");
    assert_eq!(lines[5], "");
    assert!(lines[6].starts_with("ssh-ed25519 AAAA") && lines[6].ends_with(" hello"));

    // duplicate: prints key, exits 2
    let o = e.run(&["new", "foo/bar"]);
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(String::from_utf8_lossy(&o.stdout), out);

    // rotate: new key, history kept
    let o = e.run(&["new", "foo/bar", "--rotate", "--json"]);
    assert!(o.status.success());
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_ne!(
        j["fingerprint"],
        lines[1].trim_start_matches("Fingerprint: ")
    );
    let shown = e.ok(&["show", "foo/bar"]);
    assert!(shown.contains("Previous:"), "{shown}");

    // validation
    for bad in ["foo", "../x/y", "-a/b", "a/b/../c", "a//b"] {
        assert!(!e.run(&["new", bad]).status.success(), "{bad}");
    }
}

#[test]
fn new_without_argument_uses_origin() {
    let e = Env::new();
    let work = tempfile::tempdir().unwrap();
    let git = |args: &[&str]| {
        assert!(Command::new("git")
            .current_dir(work.path())
            .args(args)
            .output()
            .unwrap()
            .status
            .success());
    };
    git(&["init", "-q"]);
    for (url, want) in [
        ("git@github.com:Me/Scp.git", "me/scp"),
        ("ssh://git@github.com:22/Me/Ssh.git", "me/ssh"),
        ("https://github.com/Me/Https", "me/https"),
    ] {
        let _ = Command::new("git")
            .current_dir(work.path())
            .args(["remote", "remove", "origin"])
            .output();
        git(&["remote", "add", "origin", url]);
        let o = e
            .cmd()
            .env("PATH", "/usr/bin:/bin")
            .current_dir(work.path())
            .arg("new")
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", s(&o));
        assert!(String::from_utf8_lossy(&o.stdout).starts_with(&format!("Repo:        {want}\n")));
    }
    let empty = tempfile::tempdir().unwrap();
    assert!(!e
        .cmd()
        .env("PATH", "/usr/bin:/bin")
        .current_dir(empty.path())
        .arg("new")
        .output()
        .unwrap()
        .status
        .success());
}

#[test]
fn import_export_rm_list() {
    let e = Env::new();
    // make a key elsewhere and import it
    let src = e.ok(&["new", "src/key"]);
    let pem = e.ok(&["export-private", "src/key", "--yes"]);
    assert!(!e.run(&["export-private", "src/key"]).status.success());
    let f = e.cfg.path().join("id_ed25519");
    fs::write(&f, &pem).unwrap();
    let imported = e.ok(&["import", "dst/key", f.to_str().unwrap()]);
    let fp = |t: &str| t.lines().nth(1).unwrap().to_owned();
    assert_eq!(fp(&src), fp(&imported));
    assert!(!e
        .run(&["import", "dst/key", f.to_str().unwrap()])
        .status
        .success());
    assert!(e
        .run(&["import", "dst/key", f.to_str().unwrap(), "--force"])
        .status
        .success());
    // garbage rejected
    fs::write(&f, "nope").unwrap();
    assert!(!e
        .run(&["import", "bad/key", f.to_str().unwrap()])
        .status
        .success());

    let pubkey = e.ok(&["export-pub", "dst/key"]);
    assert!(pubkey.starts_with("ssh-ed25519 "));
    let list: serde_json::Value = serde_json::from_str(&e.ok(&["list", "--json"])).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert!(!e.ok(&["list"]).contains("PRIVATE"));
    assert!(e.run(&["rm", "dst/key"]).status.success());
    assert!(!e.run(&["rm", "dst/key"]).status.success());
    assert!(!e.run(&["export-pub", "dst/key"]).status.success());
}

#[test]
fn private_keys_never_stored_in_plaintext() {
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    let db = e.cfg.path().join("xdg/ndo4git/keys.db");
    for f in [db.clone(), db.with_extension("db-wal")] {
        if let Ok(bytes) = fs::read(&f) {
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("OPENSSH PRIVATE KEY"));
            assert!(!text.contains("b3BlbnNzaC1rZXk")); // base64 of "openssh-key"
        }
    }
    use std::os::unix::fs::MetadataExt;
    let dir = e.cfg.path().join("xdg/ndo4git");
    assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(dir.join("master.key")).unwrap().mode() & 0o777,
        0o600
    );
    // perms are repaired on start
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(dir.join("master.key"), fs::Permissions::from_mode(0o644)).unwrap();
    e.ok(&["list"]);
    assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(dir.join("master.key")).unwrap().mode() & 0o777,
        0o600
    );
}

#[test]
fn backup_and_restore_roundtrip() {
    let a = Env::new();
    let pem_a = {
        a.ok(&["new", "o/r", "--write"]);
        a.ok(&["export-private", "o/r", "--yes"])
    };
    let file = a.cfg.path().join("backup.n4g");
    a.ok(&["backup", file.to_str().unwrap()]);
    assert!(
        !a.run(&["backup", file.to_str().unwrap()]).status.success(),
        "no clobber"
    );
    assert!(fs::read(&file).unwrap().starts_with(b"NDO4GIT-BACKUP"));

    let b = Env::new();
    let out = b.ok(&["restore", file.to_str().unwrap()]);
    assert!(out.contains("imported: o/r"), "{out}");
    assert_eq!(b.ok(&["export-private", "o/r", "--yes"]), pem_a);
    // wrong passphrase
    let o = b
        .cmd()
        .env("NDO4GIT_BACKUP_PASSPHRASE", "wrong")
        .args(["restore", file.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!o.status.success());
    // second restore skips
    assert!(b
        .ok(&["restore", file.to_str().unwrap()])
        .contains("skipped"));
}

#[test]
fn install_requires_root() {
    if nix_is_root() {
        return;
    }
    let e = Env::new();
    let o = e.run(&["install"]);
    assert!(!o.status.success());
    assert!(s(&o).contains("must be run as root"), "{}", s(&o));
    assert!(!e.run(&["uninstall"]).status.success());
}

fn nix_is_root() -> bool {
    Path::new("/proc/self")
        .metadata()
        .is_ok_and(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0)
}

#[test]
fn doctor_warns_about_overrides() {
    let e = Env::new();
    let o = e
        .cmd()
        .env("GIT_SSH_COMMAND", "ssh -v")
        .args(["doctor", "--json"])
        .output()
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let warn = j.as_array().unwrap().iter().any(|c| {
        c["status"] == "warn" && c["detail"].as_str().unwrap().contains("GIT_SSH_COMMAND")
    });
    assert!(warn, "{j}");
}

#[test]
fn completions_and_man_work() {
    let e = Env::new();
    assert!(e.ok(&["completions", "bash"]).contains("ndo4git"));
    assert!(e.ok(&["man"]).contains(".TH ndo4git"));
}

/// Regression: OpenSSH closes inherited descriptors at startup, so the key
/// must be reachable by *path* (holder process), not via an inherited fd.
#[test]
fn real_openssh_can_load_the_key() {
    if !Path::new("/usr/bin/ssh").exists() {
        return;
    }
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    let o = e
        .cmd()
        .env("PATH", "/usr/bin:/bin")
        .arg("ssh-wrapper")
        .args([
            "-vv",
            "-F",
            "/dev/null",
            "-o",
            "BatchMode=yes",
            "-o",
            "ProxyCommand=true",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "git@github.com",
            "git-upload-pack 'o/r'",
        ])
        .output()
        .unwrap();
    let err = s(&o);
    assert!(!err.contains("not accessible"), "{err}");
    assert!(err.contains("identity file /proc/"), "{err}");
    assert!(!err.contains("no such identity"), "{err}");
    // ed25519 private key was parsed by ssh itself
    assert!(err.contains("type 2"), "{err}");
}

#[test]
fn github_codeberg_and_gitlab_work_out_of_the_box() {
    let e = Env::new();
    let gh = e.ok(&["new", "o/r"]);
    let cb = e.ok(&["new", "ssh://git@codeberg.org/NDO4ME/git.git"]);
    let gl = e.ok(&["new", "git@gitlab.com:Group/Sub/Proj.git"]);
    assert!(
        gh.contains("\nhttps://github.com/o/r/settings/keys/new\n"),
        "{gh}"
    );
    assert!(
        cb.contains("\nhttps://codeberg.org/ndo4me/git/settings/keys\n"),
        "{cb}"
    );
    assert!(
        gl.contains(
            "\nhttps://gitlab.com/group/sub/proj/-/settings/repository#js-deploy-keys-settings\n"
        ),
        "{gl}"
    );
    let j: serde_json::Value =
        serde_json::from_str(&e.ok(&["new", "codeberg.org/a/b", "--json"])).unwrap();
    assert_eq!(j["forge"], "forgejo");

    for (host, cmd, repo) in [
        (
            "codeberg.org",
            "git-upload-pack '/NDO4ME/git.git'",
            "ndo4me/git",
        ),
        (
            "gitlab.com",
            "git-receive-pack 'group/sub/proj.git'",
            "group/sub/proj",
        ),
        (
            "gitlab.com",
            "git-lfs-authenticate '/Group/Sub/Proj.git' upload",
            "group/sub/proj",
        ),
        ("github.com", "git-upload-pack 'o/r.git'", "o/r"),
    ] {
        e.clear_log();
        let dest = format!("git@{host}");
        assert!(
            e.wrapper(&["-p", "22", &dest, cmd]).status.success(),
            "{repo}"
        );
        assert_managed(&e.argv_lines()[0], &["-p", "22", &dest, cmd]);
    }
    // keys are per host: same path on another forge is unmanaged
    e.clear_log();
    assert!(e
        .wrapper(&["git@gitlab.com", "git-upload-pack 'ndo4me/git'"])
        .status
        .success());
    assert_eq!(
        e.argv_lines()[0],
        ["git@gitlab.com", "git-upload-pack 'ndo4me/git'"]
    );

    // self-hosted instance with an explicit forge kind
    e.ok(&["host", "add", "git.example.org", "--forge", "gitlab"]);
    let own = e.ok(&["new", "git.example.org/team/proj"]);
    assert!(
        own.contains("/-/settings/repository#js-deploy-keys-settings"),
        "{own}"
    );
    assert!(e.ok(&["host", "list"]).contains("git.example.org\tgitlab"));
    assert!(!e
        .run(&["host", "add", "x.example", "--forge", "bogus"])
        .status
        .success());
}
