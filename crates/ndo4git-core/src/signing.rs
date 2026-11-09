//! Verification of release signatures (`ssh-keygen -Y sign` format).
//!
//! Release assets are signed with a dedicated ed25519 key; its public half is
//! compiled into the binary. `ndo4git update` refuses anything that does not
//! verify, so a compromised download host alone cannot ship code.

use crate::error::{Error, Result};
use ssh_key::{PublicKey, SshSig};

/// Namespace used when signing (`ssh-keygen -Y sign -n ndo4git-release`).
pub const NAMESPACE: &str = "ndo4git-release";

/// Verify `sig_armored` (an `-----BEGIN SSH SIGNATURE-----` block) over `data`
/// with the OpenSSH-format public key `pubkey`.
pub fn verify(pubkey: &str, data: &[u8], sig_armored: &str) -> Result<()> {
    let key = PublicKey::from_openssh(pubkey.trim())
        .map_err(|e| Error::Invalid(format!("bad release public key: {e}")))?;
    let sig = SshSig::from_pem(sig_armored.trim())
        .map_err(|e| Error::Invalid(format!("unreadable signature: {e}")))?;
    if sig.namespace() != NAMESPACE {
        return Err(Error::Invalid(format!(
            "signature namespace {:?} is not {NAMESPACE:?}",
            sig.namespace()
        )));
    }
    key.verify(NAMESPACE, data, &sig)
        .map_err(|_| Error::Invalid("signature does not match the release key".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::{rand_core::OsRng, Algorithm, HashAlg, LineEnding, PrivateKey};

    fn sign(key: &PrivateKey, ns: &str, data: &[u8]) -> String {
        key.sign(ns, HashAlg::Sha512, data)
            .unwrap()
            .to_pem(LineEnding::LF)
            .unwrap()
    }

    #[test]
    fn good_and_bad_signatures() {
        let k = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pubk = k.public_key().to_openssh().unwrap();
        let sig = sign(&k, NAMESPACE, b"binary bytes");
        assert!(verify(&pubk, b"binary bytes", &sig).is_ok());
        assert!(verify(&pubk, b"tampered", &sig).is_err());
        let wrong_signer = sign(&other, NAMESPACE, b"binary bytes");
        assert!(verify(&pubk, b"binary bytes", &wrong_signer).is_err());
        let wrong_ns = sign(&k, "something-else", b"binary bytes");
        assert!(verify(&pubk, b"binary bytes", &wrong_ns).is_err());
        assert!(verify(&pubk, b"binary bytes", "garbage").is_err());
        assert!(verify("not a key", b"x", &sig).is_err());
    }
}
