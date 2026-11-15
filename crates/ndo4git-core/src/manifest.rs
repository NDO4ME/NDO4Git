//! The manifest: one declarative TOML file that is the single source of truth.
//!
//! Everything ndo4git can derive (managed hosts, key presence, aliases,
//! per-repository git identities, performance settings) is described here and
//! reconciled by [`crate::plan`]. Parsing is strict (`deny_unknown_fields`) and
//! every value that ends up in a gitconfig file is validated, so a manifest can
//! never smuggle in extra config keys or executable settings.

use crate::error::{Error, Result};
use crate::exec::HostKeyPolicy;
use crate::forge::Forge;
use crate::repo::{normalize_host, parse_target, DEFAULT_HOST};
use serde::Deserialize;
use std::collections::BTreeMap;

pub const MANIFEST_FILE: &str = "manifest.toml";
pub const SUPPORTED_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    /// Apply the conservative performance preset (see [`PERF_PRESET`]).
    #[serde(default)]
    pub perf: bool,
    /// Also remove hosts and aliases that the manifest does not list.
    /// Keys are never deleted by `apply`.
    #[serde(default)]
    pub prune: bool,
    #[serde(default)]
    pub hostkey: Option<String>,
    /// `host = "forge"` (github, gitlab, forgejo).
    #[serde(default)]
    pub hosts: BTreeMap<String, String>,
    /// Repositories that must have a key (`OWNER/REPO` or `HOST/PATH`).
    #[serde(default)]
    pub keys: Vec<String>,
    /// `old = "new"`: `old` uses the key of `new`.
    #[serde(default)]
    pub aliases: BTreeMap<String, String>,
    /// Extra git settings (allow-listed keys only).
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    /// Git identities, applied through `includeIf`; later entries win.
    #[serde(default, rename = "identity")]
    pub identities: Vec<Identity>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    /// Path of an SSH public key used to sign commits (`gpg.format = ssh`).
    pub signing_key: Option<String>,
    /// `HOST/PATTERN` globs (`*` matches anything), e.g. `github.com/acme/*`.
    #[serde(rename = "match")]
    pub matches: Vec<String>,
}

/// Settings applied by `perf = true`. Each one is cheap, daemon-free and
/// reduces work: fewer process spawns, parallel fetch, incremental indexes.
pub const PERF_PRESET: &[(&str, &str)] = &[
    // git otherwise probes `ssh -G` (one extra process) on every command
    ("ssh.variant", "ssh"),
    ("fetch.parallel", "0"),
    ("fetch.writeCommitGraph", "true"),
    ("feature.manyFiles", "true"),
    ("pack.threads", "0"),
    ("gc.auto", "6700"),
    ("maintenance.auto", "true"),
    ("protocol.version", "2"),
    ("fetch.negotiationAlgorithm", "skipping"),
];

/// Prefixes / exact keys a manifest may set. Anything that can run a program
/// (`core.sshCommand`, `core.fsmonitor`, `core.hooksPath`, `alias.*`,
/// `credential.*`, `filter.*`, `gpg.program`, …) is deliberately absent.
const ALLOWED_PREFIXES: &[&str] = &[
    "fetch.",
    "feature.",
    "pull.",
    "push.",
    "rebase.",
    "gc.",
    "maintenance.auto",
    "maintenance.strategy",
    "pack.",
    "protocol.version",
    "status.",
    "transfer.",
    "index.",
    "checkout.",
    "log.",
    "branch.autosetuprebase",
    "branch.autosetupmerge",
    "init.defaultbranch",
    "merge.conflictstyle",
    "diff.algorithm",
    "core.untrackedcache",
    "core.commitgraph",
    "core.preloadindex",
    "core.fscache",
    "core.sparsecheckout",
    "core.autocrlf",
    "core.filemode",
    "ssh.variant",
    "commit.verbose",
    "commit.gpgsign",
    "tag.gpgsign",
    "rerere.enabled",
    "help.autocorrect",
];

fn bad(m: impl Into<String>) -> Error {
    Error::Invalid(m.into())
}

fn no_control(what: &str, v: &str) -> Result<()> {
    if v.chars().any(char::is_control) {
        return Err(bad(format!("{what} must not contain control characters")));
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// A git config key: `section.key` or `section.sub.key`, restricted charset.
fn check_setting_key(key: &str) -> Result<String> {
    let lower = key.to_ascii_lowercase();
    let ok_chars = lower
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let parts = lower.split('.').count();
    if !ok_chars || !(2..=3).contains(&parts) || lower.split('.').any(str::is_empty) {
        return Err(bad(format!("invalid git setting name {key:?}")));
    }
    if !ALLOWED_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        return Err(bad(format!(
            "git setting {key:?} is not allowed in a manifest (only performance/workflow settings are)"
        )));
    }
    Ok(key.to_owned())
}

/// A `match` glob: `HOST/PATTERN`. Returns `(host, pattern)`.
pub fn parse_match(m: &str) -> Result<(String, String)> {
    let (host, pat) = m
        .split_once('/')
        .ok_or_else(|| bad(format!("match {m:?} must look like HOST/PATTERN")))?;
    let host = normalize_host(host)?;
    let pat = pat.trim_matches('/');
    let ok = !pat.is_empty()
        && pat.len() <= 200
        && !pat.contains("..")
        && pat
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b'*'));
    if !ok {
        return Err(bad(format!(
            "match {m:?}: pattern may only contain letters, digits, . _ - / and *"
        )));
    }
    // `**` and `*` are the same for our purposes
    let mut collapsed = String::with_capacity(pat.len());
    for c in pat.chars() {
        if !(c == '*' && collapsed.ends_with('*')) {
            collapsed.push(c);
        }
    }
    Ok((host, collapsed))
}

/// Case-insensitive glob where `*` matches any run of characters (including `/`).
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi].eq_ignore_ascii_case(&t[ti]) {
            pi += 1;
            ti += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// A repository reference from the manifest, resolved to `(host, repo)`.
pub fn resolve_ref(s: &str) -> Result<(String, String)> {
    let (host, repo) = parse_target(s)?;
    Ok((host.unwrap_or_else(|| DEFAULT_HOST.to_owned()), repo))
}

impl Manifest {
    /// Parse and validate.
    pub fn parse(text: &str) -> Result<Self> {
        let m: Self = toml::from_str(text).map_err(|e| bad(format!("manifest: {e}")))?;
        m.validate()?;
        Ok(m)
    }

    fn validate(&self) -> Result<()> {
        if self.version != SUPPORTED_VERSION {
            return Err(bad(format!(
                "manifest version {} is not supported (this ndo4git understands version {SUPPORTED_VERSION})",
                self.version
            )));
        }
        if let Some(p) = &self.hostkey {
            if HostKeyPolicy::parse(p).is_none() {
                return Err(bad(format!(
                    "manifest hostkey {p:?}: expected accept-new, ask or strict"
                )));
            }
        }
        for (h, f) in &self.hosts {
            normalize_host(h)?;
            if Forge::parse(f).is_none() {
                return Err(bad(format!(
                    "manifest host {h}: unknown forge {f:?} (github, gitlab, forgejo)"
                )));
            }
        }
        for k in &self.keys {
            resolve_ref(k)?;
        }
        for (a, t) in &self.aliases {
            let (ha, ra) = resolve_ref(a)?;
            let (ht, rt) = resolve_ref(t)?;
            if ha != ht {
                return Err(bad(format!("alias {a} -> {t}: hosts differ")));
            }
            if ra == rt {
                return Err(bad(format!("alias {a} points at itself")));
            }
        }
        for (k, v) in &self.settings {
            check_setting_key(k)?;
            no_control(&format!("setting {k}"), v)?;
        }
        let mut seen = std::collections::BTreeSet::new();
        for i in &self.identities {
            if !valid_id(&i.id) {
                return Err(bad(format!(
                    "identity id {:?}: use lowercase letters, digits, - and _",
                    i.id
                )));
            }
            if !seen.insert(i.id.as_str()) {
                return Err(bad(format!("duplicate identity {:?}", i.id)));
            }
            if i.matches.is_empty() {
                return Err(bad(format!("identity {}: needs at least one match", i.id)));
            }
            if i.name.is_none() && i.email.is_none() && i.signing_key.is_none() {
                return Err(bad(format!(
                    "identity {}: set name, email or signing_key",
                    i.id
                )));
            }
            for (what, v) in [
                ("name", &i.name),
                ("email", &i.email),
                ("signing_key", &i.signing_key),
            ] {
                if let Some(v) = v {
                    no_control(&format!("identity {} {what}", i.id), v)?;
                    if v.trim().is_empty() {
                        return Err(bad(format!("identity {}: {what} is empty", i.id)));
                    }
                }
            }
            for m in &i.matches {
                parse_match(m)?;
            }
        }
        Ok(())
    }

    /// Effective git settings: perf preset first, then explicit `settings`.
    #[must_use]
    pub fn effective_settings(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        if self.perf {
            for (k, v) in PERF_PRESET {
                out.insert((*k).to_owned(), (*v).to_owned());
            }
        }
        for (k, v) in &self.settings {
            out.insert(k.clone(), v.clone());
        }
        out
    }

    /// Every identity that applies to `host/repo`, in manifest order. Git includes
    /// all of them and later ones override earlier ones field by field.
    #[must_use]
    pub fn identities_for(&self, host: &str, repo: &str) -> Vec<&Identity> {
        let subject = format!("{host}/{repo}");
        self.identities
            .iter()
            .filter(|i| {
                i.matches.iter().any(|m| {
                    parse_match(m).is_ok_and(|(h, p)| glob_match(&format!("{h}/{p}"), &subject))
                })
            })
            .collect()
    }

    /// The identity that decides: the last matching one.
    #[must_use]
    pub fn identity_for(&self, host: &str, repo: &str) -> Option<&Identity> {
        self.identities_for(host, repo).pop()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
version = 1
perf = true
hostkey = "strict"
keys = ["acme/widget", "git.example.org/team/proj"]

[hosts]
"git.example.org" = "gitlab"

[aliases]
"acme/old" = "acme/widget"

[settings]
"pull.rebase" = "true"

[[identity]]
id = "work"
name = "Ada"
email = "ada@acme.example"
match = ["github.com/acme/*"]

[[identity]]
id = "oss"
email = "ada@oss.example"
match = ["codeberg.org/*", "github.com/acme/public-*"]
"#;

    #[test]
    fn parses_good_manifest() {
        let m = Manifest::parse(GOOD).unwrap();
        assert_eq!(m.identities.len(), 2);
        assert_eq!(m.effective_settings()["pull.rebase"], "true");
        assert_eq!(m.effective_settings()["ssh.variant"], "ssh");
    }

    #[test]
    fn last_matching_identity_wins() {
        let m = Manifest::parse(GOOD).unwrap();
        assert_eq!(m.identity_for("github.com", "acme/x").unwrap().id, "work");
        assert_eq!(
            m.identity_for("github.com", "acme/public-site").unwrap().id,
            "oss"
        );
        assert_eq!(m.identity_for("codeberg.org", "me/x").unwrap().id, "oss");
        assert!(m.identity_for("gitlab.com", "a/b").is_none());
    }

    #[test]
    fn glob_rules() {
        assert!(glob_match("github.com/acme/*", "github.com/ACME/widget"));
        assert!(glob_match("*", "anything/at/all"));
        assert!(glob_match("a*c", "abbbc"));
        assert!(!glob_match("a*c", "abbbd"));
        assert!(!glob_match("github.com/acme", "github.com/acme/x"));
    }

    #[test]
    fn rejects_bad_input() {
        let bad = |s: &str| Manifest::parse(s).is_err();
        assert!(bad("version = 2"));
        assert!(bad("version = 1\nunknown = 1"));
        assert!(bad("version = 1\nhostkey = \"nope\""));
        assert!(bad("version = 1\n[hosts]\n\"x.example\" = \"bogus\""));
        assert!(bad("version = 1\n[settings]\n\"core.sshCommand\" = \"x\""));
        assert!(bad("version = 1\n[settings]\n\"alias.x\" = \"!rm\""));
        assert!(bad("version = 1\n[settings]\n\"core.fsmonitor\" = \"x\""));
        assert!(bad("version = 1\n[settings]\n\"pull.rebase\" = \"a\\nb\""));
        assert!(bad(
            "version = 1\n[[identity]]\nid=\"A\"\nemail=\"e\"\nmatch=[\"github.com/*\"]"
        ));
        assert!(bad(
            "version = 1\n[[identity]]\nid=\"a\"\nemail=\"e\"\nmatch=[]"
        ));
        assert!(bad(
            "version = 1\n[[identity]]\nid=\"a\"\nemail=\"e\\nf\"\nmatch=[\"github.com/*\"]"
        ));
        assert!(bad(
            "version = 1\n[[identity]]\nid=\"a\"\nemail=\"e\"\nmatch=[\"github.com/a?b\"]"
        ));
        assert!(bad(
            "version = 1\n[[identity]]\nid=\"a\"\nemail=\"e\"\nmatch=[\"nohost\"]"
        ));
        assert!(bad("version = 1\n[aliases]\n\"a/b\" = \"a/b\""));
        assert!(bad("version = 1\nkeys = [\"../etc\"]"));
    }
}
