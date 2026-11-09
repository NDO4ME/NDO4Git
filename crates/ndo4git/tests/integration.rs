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

/// The file-staging path (used on macOS) driven by real OpenSSH: the key is
/// loadable, lives in a private 0700 directory, and disappears with ssh.
#[test]
fn file_staging_works_with_real_openssh_and_cleans_up() {
    if !Path::new("/usr/bin/ssh").exists() {
        return;
    }
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    let run = e.cfg.path().join("run");
    fs::create_dir_all(&run).unwrap();
    let o = e
        .cmd()
        .env("PATH", "/usr/bin:/bin")
        .env("XDG_RUNTIME_DIR", &run)
        .env("NDO4GIT_KEY_STAGING", "file")
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
    assert!(err.contains("/ndo4git-") && err.contains("/key-"), "{err}");
    assert!(err.contains("type 2"), "{err}");
    let dir = fs::read_dir(&run).unwrap().next().unwrap().unwrap().path();
    assert_eq!(
        fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    // the holder notices ssh is gone and removes the file
    for _ in 0..40 {
        if fs::read_dir(&dir).unwrap().count() == 0 {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!(
        "staged key file was not removed: {:?}",
        fs::read_dir(&dir).unwrap().collect::<Vec<_>>()
    );
}

#[test]
fn hostkey_policy_controls_the_ssh_option() {
    let e = Env::new();
    e.ok(&["new", "o/r"]);
    assert_eq!(e.ok(&["host", "hostkey"]).trim(), "accept-new");
    let opts = |e: &Env| -> Vec<String> {
        e.clear_log();
        assert!(e
            .wrapper(&["git@github.com", "git-upload-pack 'o/r'"])
            .status
            .success());
        e.argv_lines()[0].clone()
    };
    assert!(opts(&e).contains(&"StrictHostKeyChecking=accept-new".to_owned()));
    assert_eq!(e.ok(&["host", "hostkey", "strict"]).trim(), "strict");
    let strict = opts(&e);
    assert!(
        strict.contains(&"StrictHostKeyChecking=yes".to_owned()),
        "{strict:?}"
    );
    assert!(!strict.iter().any(|a| a.contains("accept-new")));
    e.ok(&["host", "hostkey", "ask"]);
    let ask = opts(&e);
    assert!(
        !ask.iter().any(|a| a.starts_with("StrictHostKeyChecking")),
        "{ask:?}"
    );
    assert!(ask.contains(&"IdentitiesOnly=yes".to_owned()));
    assert!(!e.run(&["host", "hostkey", "bogus"]).status.success());
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

// ---------------------------------------------------------------- update

mod update {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    const CURRENT: &str = env!("CARGO_PKG_VERSION");

    /// Tiny HTTP server: path -> (status, body). Runs for the life of the test process.
    fn serve(routes: HashMap<String, (u16, Vec<u8>)>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let (code, body) = routes
                    .get(&path)
                    .cloned()
                    .unwrap_or((404, b"not found".to_vec()));
                let head = format!(
                    "HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(&body);
            }
        });
        port
    }

    fn arch_asset() -> String {
        format!("ndo4git-{}-linux-musl", std::env::consts::ARCH) // tests run on Linux
    }

    struct Fixture {
        _dir: TempDir,
        exe: PathBuf,
        port: u16,
        env: Env,
        pubkey: String,
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Sig {
        Good,
        Missing,
        WrongKey,
        WrongNamespace,
    }

    /// Generate an ed25519 key with the real `ssh-keygen`; returns (private path, public line).
    fn gen_key(dir: &Path, name: &str) -> (PathBuf, String) {
        let key = dir.join(name);
        let o = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "t", "-f"])
            .arg(&key)
            .output()
            .unwrap();
        assert!(o.status.success());
        let pubk = fs::read_to_string(dir.join(format!("{name}.pub"))).unwrap();
        (key, pubk.trim().to_owned())
    }

    /// Sign `data` exactly like scripts/release.sh does.
    fn sign_like_release(dir: &Path, key: &Path, ns: &str, data: &[u8]) -> Vec<u8> {
        let payload = dir.join("payload");
        let _ = fs::remove_file(dir.join("payload.sig"));
        fs::write(&payload, data).unwrap();
        let o = Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", ns, "-f"])
            .arg(key)
            .arg(&payload)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        fs::read(dir.join("payload.sig")).unwrap()
    }

    /// `tag`: release tag; `reported`: what the new binary prints for --version;
    /// `sha_ok`/`with_sha`: control the checksum asset.
    fn fixture(tag: &str, reported: &str, sha_ok: bool, with_sha: bool) -> Fixture {
        fixture_sig(tag, reported, sha_ok, with_sha, Sig::Good)
    }

    fn fixture_sig(tag: &str, reported: &str, sha_ok: bool, with_sha: bool, sig: Sig) -> Fixture {
        let env = Env::new();
        let dir = tempfile::tempdir().unwrap();
        let keys = tempfile::tempdir().unwrap();
        let (good_key, pubkey) = gen_key(keys.path(), "release");
        let (other_key, _) = gen_key(keys.path(), "other");
        let exe = dir.path().join("ndo4git");
        fs::copy(BIN, &exe).unwrap();
        let new_bin = format!("#!/bin/sh\necho 'ndo4git {reported}'\n").into_bytes();
        let name = arch_asset();
        let sum = if sha_ok {
            format!("{:x}", Sha256::digest(&new_bin))
        } else {
            "0".repeat(64)
        };
        let mut routes = HashMap::new();
        let signature = match sig {
            Sig::Missing => None,
            Sig::Good => Some(sign_like_release(
                keys.path(),
                &good_key,
                "ndo4git-release",
                &new_bin,
            )),
            Sig::WrongKey => Some(sign_like_release(
                keys.path(),
                &other_key,
                "ndo4git-release",
                &new_bin,
            )),
            Sig::WrongNamespace => {
                Some(sign_like_release(keys.path(), &good_key, "file", &new_bin))
            }
        };
        routes.insert("/dl/bin".to_owned(), (200, new_bin));
        if let Some(sg) = signature {
            routes.insert("/dl/sig".to_owned(), (200, sg));
        }
        routes.insert(
            "/dl/sha".to_owned(),
            (200, format!("{sum}  {name}\n").into_bytes()),
        );
        // bind first and keep the listener: the port must never be released
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let mut assets = vec![format!(
            r#"{{"name":"{name}","browser_download_url":"http://127.0.0.1:{port}/dl/bin"}}"#
        )];
        if with_sha {
            assets.push(format!(
                r#"{{"name":"{name}.sha256","browser_download_url":"http://127.0.0.1:{port}/dl/sha"}}"#
            ));
        }
        if sig != Sig::Missing {
            assets.push(format!(
                r#"{{"name":"{name}.sig","browser_download_url":"http://127.0.0.1:{port}/dl/sig"}}"#
            ));
        }
        let assets = assets.join(",");
        let json = format!(r#"{{"tag_name":"{tag}","assets":[{assets}]}}"#);
        routes.insert("/api/latest".to_owned(), (200, json.clone().into_bytes()));
        routes.insert(format!("/api/tags/{tag}"), (200, json.into_bytes()));
        std::thread::spawn(move || {
            for stream in l.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = req.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let (code, body) = routes
                    .get(&path)
                    .cloned()
                    .unwrap_or((404, b"nope".to_vec()));
                let head = format!(
                    "HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes());
                let _ = s.write_all(&body);
            }
        });
        Fixture {
            _dir: dir,
            exe,
            port,
            env,
            pubkey,
        }
    }

    impl Fixture {
        fn update(&self, extra: &[&str]) -> Output {
            // Freshly copied executables can hit ETXTBSY when another test thread forks
            // while the copy's write fd is still open; retry briefly.
            for attempt in 0..50 {
                let mut c = Command::new(&self.exe);
                c.env_clear()
                    .env("XDG_CONFIG_HOME", self.env.cfg.path().join("xdg"))
                    .env(
                        "NDO4GIT_RELEASES_API",
                        format!("http://127.0.0.1:{}/api", self.port),
                    )
                    .env("NDO4GIT_TEST_RELEASE_PUBKEY", &self.pubkey)
                    .arg("update")
                    .args(extra);
                match c.output() {
                    Err(e) if e.raw_os_error() == Some(26) && attempt < 49 => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    other => return other.unwrap(),
                }
            }
            unreachable!()
        }
        fn is_original(&self) -> bool {
            fs::read(&self.exe).unwrap() == fs::read(BIN).unwrap()
        }
        fn litter(&self) -> usize {
            fs::read_dir(self.exe.parent().unwrap()).unwrap().count()
        }
    }

    #[test]
    fn unsigned_or_wrongly_signed_releases_are_refused() {
        for (sig, needle) in [
            (Sig::Missing, "unsigned"),
            (Sig::WrongKey, "does not match"),
            (Sig::WrongNamespace, "namespace"),
        ] {
            let f = fixture_sig("v99.0.0", "99.0.0", true, true, sig);
            let o = f.update(&[]);
            assert!(!o.status.success());
            let err = String::from_utf8_lossy(&o.stderr).into_owned();
            assert!(err.contains(needle), "{needle}: {err}");
            assert!(f.is_original(), "binary must stay untouched");
            assert_eq!(f.litter(), 1);
        }
    }

    #[test]
    fn up_to_date_and_check() {
        let f = fixture(&format!("v{CURRENT}"), CURRENT, true, true);
        let o = f.update(&[]);
        assert!(o.status.success());
        assert!(String::from_utf8_lossy(&o.stdout).contains("up to date"));
        assert!(f.is_original());

        let f = fixture("v99.0.0", "99.0.0", true, true);
        let o = f.update(&["--check"]);
        assert!(o.status.success(), "{}", s(&o));
        assert!(String::from_utf8_lossy(&o.stdout).contains("update available"));
        assert!(f.is_original());
    }

    #[test]
    fn updates_in_place() {
        let f = fixture("v99.0.0", "99.0.0", true, true);
        let o = f.update(&[]);
        assert!(o.status.success(), "{}", s(&o));
        assert!(String::from_utf8_lossy(&o.stdout).contains(&format!("{CURRENT} -> 99.0.0")));
        assert!(!f.is_original());
        assert_eq!(
            fs::read_to_string(&f.exe).unwrap(),
            "#!/bin/sh\necho 'ndo4git 99.0.0'\n"
        );
        assert_eq!(
            fs::metadata(&f.exe).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(f.litter(), 1, "no staging files left behind");
        // explicit version
        let f = fixture("v99.0.0", "99.0.0", true, true);
        assert!(f.update(&["--version", "99.0.0"]).status.success());
        assert!(!f.is_original());
    }

    #[test]
    fn refuses_bad_downloads() {
        // wrong checksum
        let f = fixture("v99.0.0", "99.0.0", false, true);
        let o = f.update(&[]);
        assert!(!o.status.success());
        assert!(s(&o).contains("checksum mismatch"), "{}", s(&o));
        assert!(f.is_original());
        assert_eq!(f.litter(), 1);
        // no checksum asset
        let f = fixture("v99.0.0", "99.0.0", true, false);
        let o = f.update(&[]);
        assert!(!o.status.success());
        assert!(s(&o).contains("sha256"), "{}", s(&o));
        assert!(f.is_original());
        // binary that does not report the expected version
        let f = fixture("v99.0.0", "1.0.0", true, true);
        let o = f.update(&[]);
        assert!(!o.status.success());
        assert!(s(&o).contains("self-test"), "{}", s(&o));
        assert!(f.is_original());
        assert_eq!(f.litter(), 1);
    }

    #[test]
    fn missing_release_is_reported() {
        let port = serve(HashMap::new());
        let e = Env::new();
        let o = e
            .cmd()
            .env(
                "NDO4GIT_RELEASES_API",
                format!("http://127.0.0.1:{port}/api"),
            )
            .arg("update")
            .output()
            .unwrap();
        assert!(!o.status.success());
        assert!(s(&o).contains("no matching release"), "{}", s(&o));
    }
}
