//! Encryption at rest: master key handling and XChaCha20-Poly1305 sealing.

use crate::error::{Error, IoContext, Result};
use crate::paths::{o_nofollow, MASTER_KEY_FILE};
use chacha20poly1305::aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use secrecy::{ExposeSecret, SecretBox};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

pub const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

/// The 32-byte key that encrypts every private key in the database.
pub struct MasterKey(SecretBox<[u8; KEY_LEN]>);

impl MasterKey {
    fn from_bytes(b: [u8; KEY_LEN]) -> Self {
        Self(SecretBox::new(Box::new(b)))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(self.0.expose_secret().into())
    }

    /// Load the master key; never creates it (hot path).
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(MASTER_KEY_FILE);
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(o_nofollow())
            .open(&path)
            .ctx(format!("opening {}", path.display()))?;
        let meta = f.metadata().ctx("stat master.key")?;
        if meta.mode() & 0o077 != 0 {
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .ctx("fixing master.key permissions")?;
        }
        let mut buf = Zeroizing::new([0u8; KEY_LEN + 1]);
        let n = read_full(&mut f, &mut buf[..]).ctx("reading master.key")?;
        if n != KEY_LEN {
            return Err(Error::Crypto(format!(
                "{} is corrupt (expected {KEY_LEN} bytes, found {n})",
                path.display()
            )));
        }
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&buf[..KEY_LEN]);
        Ok(Self::from_bytes(k))
    }

    /// Load the master key, generating it on first use.
    ///
    /// Creation is race-free: the key is written to a private temp file and
    /// hard-linked into place, which fails atomically if another process won.
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        match Self::load(dir) {
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {}
            other => return other,
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut key[..]);
        let mut rnd = [0u8; 8];
        OsRng.fill_bytes(&mut rnd);
        let tmp = dir.join(format!(
            ".master.key.tmp.{}.{}",
            std::process::id(),
            rnd.iter()
                .fold(String::new(), |s, b| s + &format!("{b:02x}"))
        ));
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .ctx(format!("creating {}", tmp.display()))?;
            f.write_all(&key[..]).ctx("writing master key")?;
            f.sync_all().ctx("syncing master key")?;
        }
        let dest = dir.join(MASTER_KEY_FILE);
        let linked = fs::hard_link(&tmp, &dest);
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => Ok(Self::from_bytes(*key)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Self::load(dir),
            Err(e) => Err(e).ctx(format!("installing {}", dest.display())),
        }
    }

    /// Encrypt `plaintext`, binding `aad`. Returns `(ciphertext, nonce)`.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ct = self
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Crypto("encryption failed".into()))?;
        Ok((ct, nonce))
    }

    /// Decrypt a record produced by [`MasterKey::seal`].
    pub fn open(&self, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if nonce.len() != NONCE_LEN {
            return Err(Error::Crypto("bad nonce length".into()));
        }
        self.cipher()
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| {
                Error::Crypto("decryption failed (wrong master.key or corrupted record)".into())
            })
    }
}

fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// Additional authenticated data binding a ciphertext to its row identity, so
/// records cannot be swapped between repositories.
#[must_use]
pub fn record_aad(repo: &str, host: &str, algo: &str) -> Vec<u8> {
    format!("ndo4git:v1:{host}:{repo}:{algo}").into_bytes()
}

// ---------------------------------------------------------------- passphrase blobs

const BLOB_MAGIC: &[u8] = b"NDO4GIT-BACKUP\x01";
const SALT_LEN: usize = 16;

fn derive(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2::Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut out[..])
        .map_err(|e| Error::Crypto(format!("key derivation failed: {e}")))?;
    Ok(out)
}

/// Encrypt `data` with a passphrase (Argon2id + XChaCha20-Poly1305).
/// Layout: magic | salt(16) | nonce(24) | ciphertext+tag.
pub fn encrypt_with_passphrase(passphrase: &str, data: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive(passphrase, &salt)?;
    let mk = MasterKey::from_bytes(*key);
    let (ct, nonce) = mk.seal(BLOB_MAGIC, data)?;
    let mut out = Vec::with_capacity(BLOB_MAGIC.len() + SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(BLOB_MAGIC);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`encrypt_with_passphrase`].
pub fn decrypt_with_passphrase(passphrase: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let rest = blob
        .strip_prefix(BLOB_MAGIC)
        .ok_or_else(|| Error::Crypto("not an ndo4git backup file".into()))?;
    if rest.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(Error::Crypto("backup file is truncated".into()));
    }
    let (salt, rest) = rest.split_at(SALT_LEN);
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let key = derive(passphrase, salt)?;
    MasterKey::from_bytes(*key)
        .open(BLOB_MAGIC, nonce, ct)
        .map_err(|_| Error::Crypto("wrong passphrase or corrupted backup".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_aad_binding() {
        let mk = MasterKey::from_bytes([7; 32]);
        let aad = record_aad("o/r", "github.com", "ssh-ed25519");
        let (ct, nonce) = mk.seal(&aad, b"secret").unwrap();
        assert_ne!(&ct[..6], b"secret");
        assert_eq!(&mk.open(&aad, &nonce, &ct).unwrap()[..], b"secret");
        let other = record_aad("o/other", "github.com", "ssh-ed25519");
        assert!(mk.open(&other, &nonce, &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(mk.open(&aad, &nonce, &bad).is_err());
        assert!(MasterKey::from_bytes([8; 32])
            .open(&aad, &nonce, &ct)
            .is_err());
    }

    #[test]
    fn nonces_are_unique() {
        let mk = MasterKey::from_bytes([1; 32]);
        let (_, a) = mk.seal(b"", b"x").unwrap();
        let (_, b) = mk.seal(b"", b"x").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn master_key_create_is_idempotent_and_0600() {
        let t = tempfile::tempdir().unwrap();
        let a = MasterKey::load_or_create(t.path()).unwrap();
        let b = MasterKey::load_or_create(t.path()).unwrap();
        assert_eq!(a.0.expose_secret(), b.0.expose_secret());
        let mode = fs::metadata(t.path().join(MASTER_KEY_FILE)).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(MasterKey::load(&t.path().join("nope")).is_err());
        // no temp files left behind
        assert_eq!(fs::read_dir(t.path()).unwrap().count(), 1);
    }

    #[test]
    fn corrupt_master_key_rejected() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join(MASTER_KEY_FILE), b"short").unwrap();
        assert!(matches!(
            MasterKey::load_or_create(t.path()),
            Err(Error::Crypto(_))
        ));
    }

    #[test]
    fn passphrase_blob() {
        let blob = encrypt_with_passphrase("pw", b"hello").unwrap();
        assert_eq!(&decrypt_with_passphrase("pw", &blob).unwrap()[..], b"hello");
        assert!(decrypt_with_passphrase("nope", &blob).is_err());
        assert!(decrypt_with_passphrase("pw", b"garbage").is_err());
        assert!(decrypt_with_passphrase("pw", &blob[..blob.len() - 1]).is_err());
    }
}
