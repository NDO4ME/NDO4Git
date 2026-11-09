//! In-process ed25519 key generation and import (no `ssh-keygen`).

use crate::error::{Error, Result};
use ssh_key::{rand_core::OsRng, Algorithm, HashAlg, LineEnding, PrivateKey};
use zeroize::Zeroizing;

/// A key in the forms we need.
pub struct KeyMaterial {
    /// OpenSSH private key PEM (ends with a newline).
    pub private_openssh: Zeroizing<String>,
    /// One-line public key including the comment.
    pub public_openssh: String,
    /// `SHA256:...`
    pub fingerprint: String,
    /// Algorithm name, e.g. `ssh-ed25519`.
    pub algo: String,
}

/// Default key comment: `ndo4git:owner/repo@hostname`.
#[must_use]
pub fn default_comment(repo: &str, hostname: &str) -> String {
    format!("ndo4git:{repo}@{hostname}")
}

/// Comments end up on one line of `authorized_keys`-style output.
pub fn validate_comment(c: &str) -> Result<()> {
    if c.chars().any(char::is_control) {
        return Err(Error::Invalid(
            "comment must not contain control characters".into(),
        ));
    }
    Ok(())
}

fn material(mut key: PrivateKey, comment: Option<&str>) -> Result<KeyMaterial> {
    if let Some(c) = comment {
        validate_comment(c)?;
        key.set_comment(c);
    }
    let private_openssh = key.to_openssh(LineEnding::LF)?;
    let public = key.public_key();
    Ok(KeyMaterial {
        private_openssh,
        public_openssh: public.to_openssh()?,
        fingerprint: public.fingerprint(HashAlg::Sha256).to_string(),
        algo: key.algorithm().as_str().to_owned(),
    })
}

/// Generate a fresh ed25519 key.
pub fn generate(comment: &str) -> Result<KeyMaterial> {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)?;
    material(key, Some(comment))
}

/// Parse an OpenSSH private key (unencrypted). `comment` overrides the stored one.
pub fn from_private_openssh(pem: &str, comment: Option<&str>) -> Result<KeyMaterial> {
    let key = PrivateKey::from_openssh(pem)?;
    if key.is_encrypted() {
        return Err(Error::Invalid(
            "the private key is passphrase-protected; remove the passphrase first \
             (ssh-keygen -p -N '' -f FILE) — git runs non-interactively"
                .into(),
        ));
    }
    material(key, comment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_reimport() {
        let k = generate("ndo4git:o/r@box").unwrap();
        assert!(k
            .private_openssh
            .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
        assert!(k.private_openssh.ends_with('\n'));
        assert!(k.public_openssh.starts_with("ssh-ed25519 AAAA"));
        assert!(k.public_openssh.ends_with(" ndo4git:o/r@box"));
        assert!(k.fingerprint.starts_with("SHA256:"));
        assert_eq!(k.algo, "ssh-ed25519");
        let again = from_private_openssh(&k.private_openssh, None).unwrap();
        assert_eq!(again.fingerprint, k.fingerprint);
        assert_eq!(again.public_openssh, k.public_openssh);
        let recomment = from_private_openssh(&k.private_openssh, Some("x")).unwrap();
        assert!(recomment.public_openssh.ends_with(" x"));
    }

    #[test]
    fn rejects_garbage_and_bad_comment() {
        assert!(from_private_openssh("not a key", None).is_err());
        assert!(generate("a\nb").is_err());
    }

    #[test]
    fn keys_are_unique() {
        assert_ne!(
            generate("a").unwrap().fingerprint,
            generate("a").unwrap().fingerprint
        );
    }
}
