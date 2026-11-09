//! Output formatting for key information.

use ndo4git_core::db::KeyRow;
use ndo4git_core::forge::Forge;
use serde::Serialize;

#[must_use]
pub fn settings_url(forge: Forge, host: &str, repo: &str) -> String {
    forge.deploy_key_url(host, repo)
}

/// The exact human-readable block printed by `new`.
#[must_use]
pub fn new_block(k: &KeyRow, forge: Forge) -> String {
    format!(
        "Repo:        {}\nFingerprint: {}\nAdd this public key at:\n{}\n(Allow write access: {})\n\n{}\n",
        k.repo,
        k.fingerprint,
        settings_url(forge, &k.host, &k.repo),
        if k.can_write { "yes" } else { "no" },
        k.public_key
    )
}

#[derive(Serialize)]
pub struct NewJson<'a> {
    pub repo: &'a str,
    pub host: &'a str,
    pub fingerprint: &'a str,
    pub public_key: &'a str,
    pub can_write: bool,
    pub forge: &'static str,
    pub settings_url: String,
    pub created: bool,
}

#[must_use]
pub fn new_json(k: &KeyRow, forge: Forge, created: bool) -> NewJson<'_> {
    NewJson {
        repo: &k.repo,
        host: &k.host,
        fingerprint: &k.fingerprint,
        public_key: &k.public_key,
        can_write: k.can_write,
        forge: forge.name(),
        settings_url: settings_url(forge, &k.host, &k.repo),
        created,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_is_exact() {
        let k = KeyRow {
            id: 1,
            repo: "o/r".into(),
            host: "github.com".into(),
            algo: "ssh-ed25519".into(),
            public_key: "ssh-ed25519 AAAA ndo4git:o/r@h".into(),
            fingerprint: "SHA256:abc".into(),
            can_write: false,
            created_at: 0,
            rotated_at: None,
            last_used_at: None,
        };
        assert_eq!(
            new_block(&k, Forge::GitHub),
            "Repo:        o/r\nFingerprint: SHA256:abc\nAdd this public key at:\nhttps://github.com/o/r/settings/keys/new\n(Allow write access: no)\n\nssh-ed25519 AAAA ndo4git:o/r@h\n"
        );
    }
}
