//! Repository-name normalisation and git remote URL parsing.
//!
//! [`normalize_repo`] is the *only* place that decides what a valid
//! `owner/repo` looks like; every other module goes through it.

use crate::error::{Error, Result};

pub const DEFAULT_HOST: &str = "github.com";

/// Hosts managed out of the box.
pub const DEFAULT_HOSTS: [&str; 3] = ["github.com", "codeberg.org", "gitlab.com"];

/// Deepest supported path (GitLab allows nested subgroups).
const MAX_COMPONENTS: usize = 10;

/// A parsed git remote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub host: String,
    pub port: Option<u16>,
    /// Normalised `owner/repo`.
    pub repo: String,
}

fn bad(msg: impl Into<String>) -> Error {
    Error::Invalid(msg.into())
}

fn valid_component(c: &str) -> bool {
    !c.is_empty()
        && c != "."
        && !c.starts_with('-')
        && !c.contains("..")
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Normalise a repository path to lowercase `owner/repo` (GitLab: `group/sub/project`).
///
/// Accepts an optional leading `/`, an optional trailing `/` and `.git`, any
/// letter case. Rejects everything that is not two or more components of
/// `[A-Za-z0-9._-]+` (2 to 10 of them), and also `..`, leading `-`, NUL bytes and newlines.
pub fn normalize_repo(input: &str) -> Result<String> {
    let s = input.trim_matches(|c: char| c == ' ' || c == '\t');
    let s = s.trim_start_matches('/');
    let s = s.trim_end_matches('/');
    let lower = s.to_ascii_lowercase();
    let s = lower.strip_suffix(".git").unwrap_or(&lower);
    let s = s.trim_end_matches('/');
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() < 2 || parts.len() > MAX_COMPONENTS {
        return Err(bad(format!(
            "invalid repository {input:?}: expected OWNER/REPO (GitLab: GROUP[/SUBGROUP...]/PROJECT)"
        )));
    }
    if !parts.iter().all(|p| valid_component(p)) {
        return Err(bad(format!(
            "invalid repository {input:?}: components must match [A-Za-z0-9._-]+ \
             and must not start with '-' or contain '..'"
        )));
    }
    Ok(parts.join("/"))
}

/// Normalise a host name (lowercase, DNS-ish characters only).
pub fn normalize_host(input: &str) -> Result<String> {
    let h = input.trim().to_ascii_lowercase();
    let ok = !h.is_empty()
        && h.len() <= 253
        && !h.starts_with(['-', '.'])
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if ok {
        Ok(h)
    } else {
        Err(bad(format!("invalid host name {input:?}")))
    }
}

/// Split `host[:port]` (bracketed IPv6 literals are rejected).
fn split_host_port(hp: &str) -> Result<(String, Option<u16>)> {
    if hp.starts_with('[') {
        return Err(bad("IPv6 literal hosts are not supported"));
    }
    match hp.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse().map_err(|_| bad(format!("invalid port {p:?}")))?;
            Ok((normalize_host(h)?, Some(port)))
        }
        None => Ok((normalize_host(hp)?, None)),
    }
}

/// Parse a git remote URL (`git@host:o/r.git`, `ssh://git@host[:port]/o/r.git`,
/// `https://host/o/r(.git)`).
pub fn parse_remote_url(url: &str) -> Result<Remote> {
    let url = url.trim();
    if url.is_empty() || url.contains(['\0', '\n', '\r']) {
        return Err(bad("empty or malformed remote URL"));
    }
    if let Some((scheme, rest)) = url.split_once("://") {
        if !matches!(
            scheme,
            "ssh" | "https" | "http" | "git" | "git+ssh" | "ssh+git"
        ) {
            return Err(bad(format!("unsupported URL scheme {scheme:?}")));
        }
        let (authority, path) = rest
            .split_once('/')
            .ok_or_else(|| bad("URL has no repository path"))?;
        let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let (host, port) = split_host_port(hostport)?;
        let path = path.split(['?', '#']).next().unwrap_or(path);
        return Ok(Remote {
            host,
            port,
            repo: normalize_repo(path)?,
        });
    }
    // scp-like: [user@]host:path — the colon must precede any slash.
    let colon = url
        .find(':')
        .ok_or_else(|| bad(format!("unrecognised remote URL {url:?}")))?;
    if url.find('/').is_some_and(|s| s < colon) {
        return Err(bad(format!("unrecognised remote URL {url:?}")));
    }
    let (left, path) = url.split_at(colon);
    let host = left.rsplit_once('@').map_or(left, |(_, h)| h);
    Ok(Remote {
        host: normalize_host(host)?,
        port: None,
        repo: normalize_repo(&path[1..])?,
    })
}

/// Parse a user-supplied target: `owner/repo`, `host/owner/repo`, or a URL.
/// With three or more segments, a first segment containing a dot is a host.
/// Returns the host if the input carried one.
pub fn parse_target(input: &str) -> Result<(Option<String>, String)> {
    let input = input.trim();
    if input.contains("://") || input.contains('@') || input.contains(':') {
        let r = parse_remote_url(input)?;
        return Ok((Some(r.host), r.repo));
    }
    let segs: Vec<&str> = input.trim_matches('/').split('/').collect();
    if segs.len() >= 3 && segs[0].contains('.') {
        let host = normalize_host(segs[0])?;
        return Ok((Some(host), normalize_repo(&segs[1..].join("/"))?));
    }
    Ok((None, normalize_repo(input)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_table() {
        let ok = [
            ("owner/repo", "owner/repo"),
            ("Owner/Repo.git", "owner/repo"),
            ("/org/repo.git", "org/repo"),
            ("org/repo/", "org/repo"),
            ("org/.github", "org/.github"),
            ("a_b/c-d.e", "a_b/c-d.e"),
            ("ORG/REPO.GIT", "org/repo"),
            ("Group/Sub.Group/Project.git", "group/sub.group/project"),
            ("/a/b/c/d/e", "a/b/c/d/e"),
        ];
        for (i, want) in ok {
            assert_eq!(normalize_repo(i).unwrap(), want, "{i}");
        }
        let bad = [
            "",
            "repo",
            "../x",
            "a/..",
            "a/b..c",
            "-a/b",
            "a/-b",
            "a/b c",
            "a/b\nc",
            "a/b\0",
            "a//b",
            ".git",
            "/",
            "a/.",
            "a/b;rm",
            "a/b'c",
            "a/$(x)",
            "ünï/code",
        ];
        for i in bad {
            assert!(normalize_repo(i).is_err(), "{i:?} should be rejected");
        }
    }

    #[test]
    fn remote_urls() {
        let cases = [
            (
                "git@github.com:Owner/Repo.git",
                "github.com",
                None,
                "owner/repo",
            ),
            ("github.com:o/r", "github.com", None, "o/r"),
            ("ssh://git@github.com/o/r.git", "github.com", None, "o/r"),
            (
                "ssh://git@ghe.example.com:2222/o/r.git",
                "ghe.example.com",
                Some(2222),
                "o/r",
            ),
            ("https://github.com/o/r", "github.com", None, "o/r"),
            (
                "https://user:tok@github.com/o/r.git",
                "github.com",
                None,
                "o/r",
            ),
            ("https://GitHub.com/o/r.git?x=1", "github.com", None, "o/r"),
        ];
        for (u, h, p, r) in cases {
            let got = parse_remote_url(u).unwrap();
            assert_eq!(
                (got.host.as_str(), got.port, got.repo.as_str()),
                (h, p, r),
                "{u}"
            );
        }
        for u in [
            "",
            "nonsense",
            "./local/path",
            "ftp://x/o/r",
            "ssh://host",
            "git@h:a/b/c/d/e/f/g/h/i/j/k",
            "ssh://h:99999/o/r",
        ] {
            assert!(parse_remote_url(u).is_err(), "{u:?}");
        }
    }

    #[test]
    fn targets() {
        assert_eq!(parse_target("O/R").unwrap(), (None, "o/r".into()));
        assert_eq!(
            parse_target("ghe.corp.example/o/r").unwrap(),
            (Some("ghe.corp.example".into()), "o/r".into())
        );
        assert_eq!(
            parse_target("git@github.com:o/r.git").unwrap(),
            (Some("github.com".into()), "o/r".into())
        );
        assert_eq!(
            parse_target("gitlab.com/Group/Sub/Proj").unwrap(),
            (Some("gitlab.com".into()), "group/sub/proj".into())
        );
        assert_eq!(
            parse_target("git@gitlab.com:group/sub/proj.git").unwrap(),
            (Some("gitlab.com".into()), "group/sub/proj".into())
        );
        assert_eq!(parse_target("group/sub/proj").unwrap().1, "group/sub/proj");
    }
}
