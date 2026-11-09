//! Differences between git hosting services that matter to ndo4git.
//!
//! The SSH transport is identical everywhere (`git-upload-pack '<path>'`), so
//! the only forge-specific parts are where the user registers the public key
//! and how an unknown host is classified.

use std::fmt;

/// Supported hosting software.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forge {
    /// github.com and GitHub Enterprise.
    GitHub,
    /// Forgejo / Gitea, e.g. codeberg.org.
    Forgejo,
    /// gitlab.com and self-managed GitLab (nested groups supported).
    GitLab,
}

impl Forge {
    /// Parse a user-supplied name (`--forge`).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "github" | "ghe" => Some(Self::GitHub),
            "forgejo" | "gitea" | "codeberg" => Some(Self::Forgejo),
            "gitlab" => Some(Self::GitLab),
            _ => None,
        }
    }

    /// Best guess from the host name. Unknown hosts are treated as GitHub
    /// Enterprise; override with `ndo4git host add <host> --forge …`.
    #[must_use]
    pub fn detect(host: &str) -> Self {
        let h = host.to_ascii_lowercase();
        if h.contains("gitlab") {
            Self::GitLab
        } else if ["codeberg", "forgejo", "gitea"]
            .iter()
            .any(|k| h.contains(k))
        {
            Self::Forgejo
        } else {
            Self::GitHub
        }
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::Forgejo => "forgejo",
            Self::GitLab => "gitlab",
        }
    }

    /// Page where the public key is added as a deploy key for `repo`.
    #[must_use]
    pub fn deploy_key_url(self, host: &str, repo: &str) -> String {
        match self {
            Self::GitHub => format!("https://{host}/{repo}/settings/keys/new"),
            Self::Forgejo => format!("https://{host}/{repo}/settings/keys"),
            Self::GitLab => {
                format!("https://{host}/{repo}/-/settings/repository#js-deploy-keys-settings")
            }
        }
    }
}

impl fmt::Display for Forge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_and_urls() {
        assert_eq!(Forge::detect("github.com"), Forge::GitHub);
        assert_eq!(Forge::detect("ghe.corp.example"), Forge::GitHub);
        assert_eq!(Forge::detect("codeberg.org"), Forge::Forgejo);
        assert_eq!(Forge::detect("git.gitea.example"), Forge::Forgejo);
        assert_eq!(Forge::detect("gitlab.com"), Forge::GitLab);
        assert_eq!(Forge::detect("gitlab.example.org"), Forge::GitLab);
        assert_eq!(
            Forge::GitHub.deploy_key_url("github.com", "o/r"),
            "https://github.com/o/r/settings/keys/new"
        );
        assert_eq!(
            Forge::Forgejo.deploy_key_url("codeberg.org", "ndo4me/git"),
            "https://codeberg.org/ndo4me/git/settings/keys"
        );
        assert_eq!(
            Forge::GitLab.deploy_key_url("gitlab.com", "g/sub/p"),
            "https://gitlab.com/g/sub/p/-/settings/repository#js-deploy-keys-settings"
        );
        assert_eq!(Forge::parse("Gitea"), Some(Forge::Forgejo));
        assert_eq!(Forge::parse("nope"), None);
    }
}
