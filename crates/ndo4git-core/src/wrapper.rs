//! Pure parsing of the command line git passes to `core.sshCommand`.
//!
//! # Contract
//!
//! git runs `<sshCommand> [options] <host> <remote-command>` through the shell
//! (so our own arguments `ssh-wrapper` come first and are stripped by the
//! caller). This module receives everything after that and produces an
//! [`SshInvocation`] or a [`ParseError`]. Any error means "not ours": the
//! caller must exec the real `ssh` with the original arguments untouched.
//!
//! * Options are parsed like OpenSSH: clustered short flags (`-vvv`, `-Tp22`),
//!   option values attached (`-p22`) or separate (`-p 22`), options may also
//!   follow the host. `--` ends option parsing.
//! * The first positional word is the destination (`host`, `user@host`, or
//!   `ssh://[user@]host[:port]`); all further words, joined by single spaces,
//!   are the remote command (exactly what ssh sends to the server).
//! * `-p`, `-l` and `-o Port=`/`-o User=` are honoured, first one wins (as in
//!   ssh).
//! * `-G`, `-V`, `-Q`, `-O` mark the call as a *probe* (`probe == true`): git
//!   itself runs `ssh -G variant-test-host` to auto-detect the ssh flavour and
//!   those must always reach the real ssh unmodified.
//! * The remote command must be `git-upload-pack|git-receive-pack|
//!   git-upload-archive '<path>'` (or `git upload-pack ...`) with exactly one
//!   path argument, or the git-lfs helpers with `upload|download`; see [`extract_repo_from_command`].

use crate::repo::normalize_repo;

/// Options that consume a value (OpenSSH 9.x).
const TAKES_ARG: &str = "BbcDEeFIiJLlmOopQRSWw";
/// Options that do not.
const NO_ARG: &str = "46AaCfGgKkMNnqsTtVvXxYy";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshInvocation {
    pub user: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    /// Remote command, if any.
    pub command: Option<String>,
    /// `-G`, `-V`, `-Q` or `-O` was given: never manage this call.
    pub probe: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("unknown ssh option -{0}")]
    UnknownOption(char),
    #[error("option -{0} requires a value")]
    MissingValue(char),
    #[error("invalid port {0:?}")]
    BadPort(String),
    #[error("no destination host")]
    NoHost,
    #[error("invalid destination {0:?}")]
    BadDestination(String),
    #[error("unterminated quote in remote command")]
    UnterminatedQuote,
    #[error("remote command is not a git transport command")]
    NotGit,
    #[error("remote command has an unexpected argument list")]
    BadArity,
    #[error("invalid repository path: {0}")]
    BadRepo(String),
}

#[derive(Default)]
struct Builder {
    user: Option<String>,
    port: Option<u16>,
    probe: bool,
}

impl Builder {
    fn set_port(&mut self, v: &str) -> Result<(), ParseError> {
        let p: u16 = v
            .trim()
            .parse()
            .map_err(|_| ParseError::BadPort(v.to_owned()))?;
        self.port.get_or_insert(p);
        Ok(())
    }

    fn apply(&mut self, opt: char, val: &str) -> Result<(), ParseError> {
        match opt {
            'p' => self.set_port(val)?,
            'l' => {
                self.user.get_or_insert_with(|| val.to_owned());
            }
            'O' | 'Q' => self.probe = true,
            'o' => {
                // "Key=Value" or "Key Value"
                let (k, v) = val
                    .split_once(['=', ' ', '\t'])
                    .map_or((val, ""), |(k, v)| {
                        (k, v.trim().trim_start_matches('=').trim())
                    });
                if k.eq_ignore_ascii_case("port") {
                    self.set_port(v)?;
                } else if k.eq_ignore_ascii_case("user") {
                    self.user.get_or_insert_with(|| v.to_owned());
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// Parse an ssh destination (`host`, `user@host`, `ssh://user@host:port`).
fn parse_destination(dest: &str, b: &mut Builder) -> Result<String, ParseError> {
    let bad = || ParseError::BadDestination(dest.to_owned());
    if let Some(rest) = dest.strip_prefix("ssh://") {
        let authority = rest.split('/').next().unwrap_or(rest);
        let (user, hostport) = match authority.rsplit_once('@') {
            Some((u, h)) => (Some(u), h),
            None => (None, authority),
        };
        let (host, port) = match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        };
        if host.is_empty() {
            return Err(bad());
        }
        if let Some(p) = port {
            b.set_port(p)?;
        }
        if let Some(u) = user {
            b.user.get_or_insert_with(|| u.to_owned());
        }
        return Ok(host.to_owned());
    }
    let (user, host) = match dest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, dest),
    };
    if host.is_empty() || host.starts_with('-') {
        return Err(bad());
    }
    if let Some(u) = user {
        b.user.get_or_insert_with(|| u.to_owned());
    }
    Ok(host.to_owned())
}

/// Parse the arguments following `ndo4git ssh-wrapper` as ssh would.
#[allow(clippy::many_single_char_names)]
pub fn parse_ssh_args<S: AsRef<str>>(args: &[S]) -> Result<SshInvocation, ParseError> {
    let mut b = Builder::default();
    let mut host: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_ref();
        if a == "--" {
            i += 1;
            if host.is_none() {
                let d = args.get(i).ok_or(ParseError::NoHost)?.as_ref();
                host = Some(parse_destination(d, &mut b)?);
                i += 1;
            }
            break;
        }
        if !a.starts_with('-') || a == "-" {
            if host.is_some() {
                break; // start of the remote command
            }
            host = Some(parse_destination(a, &mut b)?);
            i += 1;
            continue;
        }
        let chars: Vec<char> = a.chars().skip(1).collect();
        let mut j = 0;
        while j < chars.len() {
            let c = chars[j];
            if TAKES_ARG.contains(c) {
                let val: String = if j + 1 < chars.len() {
                    chars[j + 1..].iter().collect()
                } else {
                    i += 1;
                    args.get(i)
                        .ok_or(ParseError::MissingValue(c))?
                        .as_ref()
                        .to_owned()
                };
                b.apply(c, &val)?;
                break;
            } else if NO_ARG.contains(c) {
                if matches!(c, 'G' | 'V') {
                    b.probe = true;
                }
            } else {
                return Err(ParseError::UnknownOption(c));
            }
            j += 1;
        }
        i += 1;
    }
    let host = host.ok_or(ParseError::NoHost)?;
    let rest: Vec<&str> = args[i.min(args.len())..]
        .iter()
        .map(AsRef::as_ref)
        .collect();
    let command = if rest.is_empty() {
        None
    } else {
        Some(rest.join(" "))
    };
    Ok(SshInvocation {
        user: b.user,
        host,
        port: b.port,
        command,
        probe: b.probe,
    })
}

/// POSIX-ish word splitting: single quotes, double quotes (with the escapes
/// backslash-quote, double backslash, backslash-dollar and backslash-backtick), backslash escapes outside quotes, adjacent pieces concatenate.
pub fn shell_split(s: &str) -> Result<Vec<String>, ParseError> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        match c {
            ' ' | '\t' | '\n' => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            '\'' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('\'') => break,
                        Some(ch) => cur.push(ch),
                        None => return Err(ParseError::UnterminatedQuote),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some(e @ ('"' | '\\' | '$' | '`')) => cur.push(e),
                            Some(other) => {
                                cur.push('\\');
                                cur.push(other);
                            }
                            None => return Err(ParseError::UnterminatedQuote),
                        },
                        Some(ch) => cur.push(ch),
                        None => return Err(ParseError::UnterminatedQuote),
                    }
                }
            }
            '\\' => {
                in_word = true;
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            _ => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

const GIT_SERVICES: [&str; 3] = ["git-upload-pack", "git-receive-pack", "git-upload-archive"];
/// git-lfs SSH helpers: `<service> '<path>' upload|download`.
const LFS_SERVICES: [&str; 2] = ["git-lfs-authenticate", "git-lfs-transfer"];

/// Extract the normalised `owner/repo` from a git remote command such as
/// `git-upload-pack 'org/Repo.git'`.
pub fn extract_repo_from_command(cmd: &str) -> Result<String, ParseError> {
    let words = shell_split(cmd)?;
    let (svc, args) = words.split_first().ok_or(ParseError::NotGit)?;
    let base = svc.rsplit('/').next().unwrap_or(svc);
    let args: &[String] = if GIT_SERVICES.contains(&base) {
        args
    } else if LFS_SERVICES.contains(&base) {
        match args {
            [path, op] if op == "upload" || op == "download" => std::slice::from_ref(path),
            _ => return Err(ParseError::BadArity),
        }
    } else if base == "git" {
        // `git upload-pack 'path'` style
        let (sub, tail) = args.split_first().ok_or(ParseError::NotGit)?;
        if !GIT_SERVICES
            .iter()
            .any(|s| s.strip_prefix("git-") == Some(sub))
        {
            return Err(ParseError::NotGit);
        }
        tail
    } else {
        return Err(ParseError::NotGit);
    };
    let [path] = args else {
        return Err(ParseError::BadArity);
    };
    normalize_repo(path).map_err(|e| ParseError::BadRepo(e.to_string()))
}

/// Case-insensitive membership test against the configured host list.
#[must_use]
pub fn host_is_configured(host: &str, configured: &[String]) -> bool {
    configured.iter().any(|h| h.eq_ignore_ascii_case(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv(args: &[&str]) -> Result<SshInvocation, ParseError> {
        parse_ssh_args(args)
    }

    #[test]
    fn typical_git_invocations() {
        let got = inv(&["git@github.com", "git-upload-pack 'o/r.git'"]).unwrap();
        assert_eq!(got.host, "github.com");
        assert_eq!(got.user.as_deref(), Some("git"));
        assert_eq!(got.port, None);
        assert_eq!(got.command.as_deref(), Some("git-upload-pack 'o/r.git'"));
        assert!(!got.probe);

        let got = inv(&[
            "-o",
            "SendEnv=GIT_PROTOCOL",
            "git@github.com",
            "git-receive-pack '/o/r.git'",
        ])
        .unwrap();
        assert_eq!(got.host, "github.com");
        assert_eq!(got.command.as_deref(), Some("git-receive-pack '/o/r.git'"));
    }

    #[test]
    fn ports() {
        for args in [
            &["-p", "2222", "git@h", "x"][..],
            &["-p2222", "git@h", "x"],
            &["-o", "Port=2222", "git@h", "x"],
            &["-oPort=2222", "git@h", "x"],
            &["-o", "Port 2222", "git@h", "x"],
            &["ssh://git@h:2222/", "x"],
            &["-4", "-Tp2222", "git@h", "x"],
            &["git@h", "-p", "2222", "x"],
            &["-p", "2222", "-p", "22", "git@h", "x"],
        ] {
            assert_eq!(inv(args).unwrap().port, Some(2222), "{args:?}");
        }
        assert_eq!(inv(&["-p", "22", "h", "x"]).unwrap().port, Some(22));
        assert_eq!(inv(&["-p22", "h", "x"]).unwrap().port, Some(22));
        assert_eq!(inv(&["h", "x"]).unwrap().port, None);
    }

    #[test]
    fn flags_and_clusters() {
        let got = inv(&["-4", "-6", "-T", "-vvv", "-q", "-x", "git@h", "c"]).unwrap();
        assert_eq!(
            (got.host.as_str(), got.command.as_deref()),
            ("h", Some("c"))
        );
        assert_eq!(
            inv(&["-lroot", "h", "c"]).unwrap().user.as_deref(),
            Some("root")
        );
        assert_eq!(
            inv(&["-l", "root", "x@h", "c"]).unwrap().user.as_deref(),
            Some("root")
        );
        assert_eq!(
            inv(&["-i", "/k", "-F", "/dev/null", "-J", "jump", "h", "c"])
                .unwrap()
                .host,
            "h"
        );
    }

    #[test]
    fn probes() {
        // what git runs to detect the ssh variant
        let g = inv(&["-G", "variant-test-host"]).unwrap();
        assert!(g.probe);
        assert_eq!(g.command, None);
        assert!(inv(&["-V"]).is_err()); // no host → not ours anyway
        assert!(inv(&["-V", "h"]).unwrap().probe);
        assert!(inv(&["-Q", "cipher", "h"]).unwrap().probe);
        assert!(inv(&["-O", "check", "h"]).unwrap().probe);
        assert!(inv(&["-TG", "h"]).unwrap().probe);
    }

    #[test]
    fn no_command_and_double_dash() {
        assert_eq!(inv(&["git@h"]).unwrap().command, None);
        let got = inv(&["--", "git@h", "-weird", "cmd"]).unwrap();
        assert_eq!(got.host, "h");
        assert_eq!(got.command.as_deref(), Some("-weird cmd"));
        let got = inv(&["h", "git-upload-pack", "'o/r'"]).unwrap();
        assert_eq!(got.command.as_deref(), Some("git-upload-pack 'o/r'"));
    }

    #[test]
    fn malformed() {
        assert_eq!(inv(&[]).unwrap_err(), ParseError::NoHost);
        assert_eq!(inv(&["-4"]).unwrap_err(), ParseError::NoHost);
        assert_eq!(inv(&["-p"]).unwrap_err(), ParseError::MissingValue('p'));
        assert!(matches!(
            inv(&["-p", "abc", "h", "c"]),
            Err(ParseError::BadPort(_))
        ));
        assert!(matches!(
            inv(&["-p", "70000", "h", "c"]),
            Err(ParseError::BadPort(_))
        ));
        assert_eq!(
            inv(&["-Z", "h", "c"]).unwrap_err(),
            ParseError::UnknownOption('Z')
        );
        assert!(matches!(
            inv(&["@", "c"]),
            Err(ParseError::BadDestination(_))
        ));
        assert!(matches!(inv(&["--"]), Err(ParseError::NoHost)));
        assert!(matches!(
            inv(&["ssh://"]),
            Err(ParseError::BadDestination(_))
        ));
    }

    #[test]
    fn repo_extraction_table() {
        let ok = [
            ("git-upload-pack 'org/repo.git'", "org/repo"),
            ("git-upload-pack '/org/repo.git'", "org/repo"),
            ("git-receive-pack 'org/repo'", "org/repo"),
            ("git-upload-archive \"Org/Repo.git\"", "org/repo"),
            ("git-upload-pack /org/repo.git", "org/repo"),
            ("git-upload-pack 'ORG/REPO.GIT'", "org/repo"),
            ("/usr/bin/git-upload-pack 'o/r'", "o/r"),
            ("git upload-pack 'o/r'", "o/r"),
            ("git-lfs-authenticate 'o/r.git' download", "o/r"),
            ("git-lfs-transfer 'o/r.git' upload", "o/r"),
            ("git-upload-pack   'o/r.git'  ", "o/r"),
            ("git-upload-pack 'o'/'r.git'", "o/r"),
            ("git-upload-pack '/Group/Sub/Proj.git'", "group/sub/proj"),
            ("git-receive-pack 'g/s1/s2/p'", "g/s1/s2/p"),
        ];
        for (c, want) in ok {
            assert_eq!(extract_repo_from_command(c).unwrap(), want, "{c}");
        }
        let bad = [
            "",
            "ls",
            "git-upload-pack",
            "git-upload-pack 'a/b' 'c/d'",
            "git-upload-pack 'a/b",
            "git-upload-pack '../etc/passwd'",
            "git-upload-pack '-oProxyCommand=x/y'",
            "git-upload-pack 'a/b; rm -rf /'",
            "git-lfs-authenticate 'a/b' bogus",
            "git-lfs-authenticate 'a/b'",
            "git foo 'a/b'",
            "git",
            "scp -t /x",
        ];
        for c in bad {
            assert!(extract_repo_from_command(c).is_err(), "{c:?}");
        }
    }

    #[test]
    fn shell_split_quotes() {
        assert_eq!(
            shell_split("a 'b c' \"d e\" f\\ g").unwrap(),
            ["a", "b c", "d e", "f g"]
        );
        assert_eq!(shell_split("'a'\\''b'").unwrap(), ["a'b"]);
        assert_eq!(shell_split("\"a\\\"b\"").unwrap(), ["a\"b"]);
        assert_eq!(shell_split("''").unwrap(), [""]);
        assert!(shell_split("'x").is_err());
        assert!(shell_split("\"x").is_err());
    }

    #[test]
    fn host_matching() {
        let l = vec!["github.com".to_owned()];
        assert!(host_is_configured("GitHub.com", &l));
        assert!(!host_is_configured("gitlab.com", &l));
    }
}

#[cfg(test)]
mod prop {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// The parser must never panic, whatever git (or an attacker) sends.
        #[test]
        fn never_panics(s in "\\PC{0,80}") {
            let _ = extract_repo_from_command(&s);
            let _ = shell_split(&s);
            let _ = parse_ssh_args(&[s.as_str(), "x"]);
        }

        /// Anything accepted is a canonical, safe `owner/repo`.
        #[test]
        fn accepted_paths_are_canonical(s in "[ -~]{0,40}") {
            let cmd = format!("git-upload-pack '{s}'");
            if let Ok(r) = extract_repo_from_command(&cmd) {
                prop_assert!(r.matches('/').count() >= 1);
                prop_assert!(!r.contains(".."));
                prop_assert!(!r.starts_with('-'));
                prop_assert!(!r.split('/').any(|c| c.starts_with('-') || c.is_empty()));
                prop_assert!(r.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-' | b'/')));
                prop_assert_eq!(crate::repo::normalize_repo(&r).unwrap(), r);
            }
        }

        /// Well-formed paths round-trip through every supported quoting style.
        #[test]
        fn roundtrip(o in "[A-Za-z0-9][A-Za-z0-9_-]{0,10}", n in "[A-Za-z0-9][A-Za-z0-9_-]{0,10}", q in 0usize..4, lead in any::<bool>(), git in any::<bool>()) {
            let path = format!("{}{o}/{n}{}", if lead { "/" } else { "" }, if git { ".git" } else { "" });
            let quoted = match q { 0 => format!("'{path}'"), 1 => format!("\"{path}\""), 2 => path.clone(), _ => format!("'{o}'/'{n}'") };
            let want = format!("{o}/{n}").to_ascii_lowercase();
            let got = extract_repo_from_command(&format!("git-receive-pack {quoted}")).unwrap();
            prop_assert_eq!(got, want);
        }
    }
}
