//! Encrypted backup / restore of all keys (passphrase protected).

use crate::crypto::{decrypt_with_passphrase, encrypt_with_passphrase, record_aad, MasterKey};
use crate::db::{Db, NewKey};
use crate::error::{Error, Result};
use crate::keygen;
use crate::repo::{normalize_host, normalize_repo};
use crate::util::now_unix;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
struct BackupKey {
    repo: String,
    host: String,
    algo: String,
    public_key: String,
    fingerprint: String,
    can_write: bool,
    created_at: i64,
    rotated_at: Option<i64>,
    last_used_at: Option<i64>,
    private_key_openssh: Zeroizing<String>,
}

#[derive(Serialize, Deserialize)]
struct BackupAlias {
    alias: String,
    host: String,
    target: String,
}

#[derive(Serialize, Deserialize)]
struct BackupFile {
    version: u32,
    created_at: i64,
    hosts: Vec<String>,
    keys: Vec<BackupKey>,
    aliases: Vec<BackupAlias>,
}

struct Ready {
    repo: String,
    host: String,
    material: keygen::KeyMaterial,
    src: BackupKey,
}

#[derive(Debug, Default)]
pub struct RestoreReport {
    pub imported: Vec<String>,
    pub replaced: Vec<String>,
    pub skipped: Vec<String>,
}

/// Serialise and encrypt the whole database.
pub fn create(db: &Db, master: &MasterKey, passphrase: &str) -> Result<Vec<u8>> {
    let mut keys = Vec::new();
    for s in db.all_secrets()? {
        let aad = record_aad(&s.row.repo, &s.row.host, &s.row.algo);
        let pem = master.open(&aad, &s.nonce, &s.private_key_enc)?;
        let pem = String::from_utf8(pem.to_vec())
            .map_err(|_| Error::Crypto("stored key is not valid UTF-8".into()))?;
        keys.push(BackupKey {
            repo: s.row.repo,
            host: s.row.host,
            algo: s.row.algo,
            public_key: s.row.public_key,
            fingerprint: s.row.fingerprint,
            can_write: s.row.can_write,
            created_at: s.row.created_at,
            rotated_at: s.row.rotated_at,
            last_used_at: s.row.last_used_at,
            private_key_openssh: Zeroizing::new(pem),
        });
    }
    let file = BackupFile {
        version: FORMAT_VERSION,
        created_at: now_unix(),
        hosts: db.hosts()?,
        keys,
        aliases: db
            .list_aliases()?
            .into_iter()
            .map(|a| BackupAlias {
                alias: a.alias,
                host: a.host,
                target: a.target,
            })
            .collect(),
    };
    let json = Zeroizing::new(serde_json::to_vec(&file)?);
    encrypt_with_passphrase(passphrase, &json)
}

/// Decrypt `blob` and merge it into `db`, re-encrypting with the local master key.
/// Existing keys are skipped unless `overwrite` is set. The whole file is
/// validated before anything is written.
pub fn restore(
    db: &mut Db,
    master: &MasterKey,
    passphrase: &str,
    blob: &[u8],
    overwrite: bool,
) -> Result<RestoreReport> {
    let json = decrypt_with_passphrase(passphrase, blob)?;
    let file: BackupFile = serde_json::from_slice(&json)?;
    if file.version != FORMAT_VERSION {
        return Err(Error::Invalid(format!(
            "unsupported backup version {}",
            file.version
        )));
    }

    let mut ready = Vec::new();
    for k in file.keys {
        let repo = normalize_repo(&k.repo)?;
        let host = normalize_host(&k.host)?;
        let material = keygen::from_private_openssh(&k.private_key_openssh, None)?;
        if material.fingerprint != k.fingerprint {
            return Err(Error::Invalid(format!(
                "fingerprint mismatch for {repo} in backup"
            )));
        }
        ready.push(Ready {
            repo,
            host,
            material,
            src: k,
        });
    }

    let mut report = RestoreReport::default();
    for r in ready {
        let label = format!("{} ({})", r.repo, r.host);
        let exists = db.get_key(&r.repo, &r.host)?.is_some();
        if exists && !overwrite {
            report.skipped.push(label);
            continue;
        }
        let aad = record_aad(&r.repo, &r.host, &r.material.algo);
        let (enc, nonce) = master.seal(&aad, r.material.private_openssh.as_bytes())?;
        let nk = NewKey {
            repo: &r.repo,
            host: &r.host,
            algo: &r.material.algo,
            public_key: &r.src.public_key,
            private_key_enc: &enc,
            nonce: &nonce,
            fingerprint: &r.material.fingerprint,
            can_write: r.src.can_write,
            created_at: r.src.created_at,
            last_used_at: r.src.last_used_at,
        };
        if exists {
            db.replace_key(&nk, now_unix(), "restore")?;
            report.replaced.push(label);
        } else {
            db.insert_key(&nk)?;
            report.imported.push(label);
        }
    }

    // hosts: union
    let mut hosts = db.hosts()?;
    for h in file.hosts {
        let h = normalize_host(&h)?;
        if !hosts.contains(&h) {
            hosts.push(h);
        }
    }
    db.set_hosts(&hosts)?;

    for a in file.aliases {
        let (alias, target, host) = (
            normalize_repo(&a.alias)?,
            normalize_repo(&a.target)?,
            normalize_host(&a.host)?,
        );
        // ignore aliases whose target did not survive (skipped/absent)
        let _ = db.add_alias(&alias, &target, &host, now_unix());
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(db: &mut Db, mk: &MasterKey, repo: &str) -> String {
        let k = keygen::generate("c").unwrap();
        let aad = record_aad(repo, "github.com", &k.algo);
        let (enc, nonce) = mk.seal(&aad, k.private_openssh.as_bytes()).unwrap();
        db.insert_key(&NewKey {
            repo,
            host: "github.com",
            algo: &k.algo,
            public_key: &k.public_openssh,
            private_key_enc: &enc,
            nonce: &nonce,
            fingerprint: &k.fingerprint,
            can_write: true,
            created_at: 5,
            last_used_at: None,
        })
        .unwrap();
        k.fingerprint.clone()
    }

    #[test]
    fn backup_restore_across_master_keys() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let mk1 = MasterKey::load_or_create(d1.path()).unwrap();
        let mk2 = MasterKey::load_or_create(d2.path()).unwrap();
        let mut db1 = Db::open_and_migrate(&d1.path().join("k.db")).unwrap();
        let mut db2 = Db::open_and_migrate(&d2.path().join("k.db")).unwrap();
        let fp = store(&mut db1, &mk1, "o/r");
        db1.add_alias("old/r", "o/r", "github.com", 1).unwrap();
        db1.set_hosts(&["github.com".into(), "ghe.example.com".into()])
            .unwrap();

        let blob = create(&db1, &mk1, "pw").unwrap();
        assert!(!String::from_utf8_lossy(&blob).contains("OPENSSH"));
        assert!(restore(&mut db2, &mk2, "bad", &blob, false).is_err());
        let rep = restore(&mut db2, &mk2, "pw", &blob, false).unwrap();
        assert_eq!(rep.imported.len(), 1);
        let s = db2.resolve_secret("old/r", "github.com").unwrap().unwrap();
        assert_eq!(s.row.fingerprint, fp);
        let aad = record_aad(&s.row.repo, &s.row.host, &s.row.algo);
        assert!(mk2.open(&aad, &s.nonce, &s.private_key_enc).is_ok());
        assert!(mk1.open(&aad, &s.nonce, &s.private_key_enc).is_err());
        assert!(db2.hosts().unwrap().contains(&"ghe.example.com".to_owned()));

        let rep = restore(&mut db2, &mk2, "pw", &blob, false).unwrap();
        assert_eq!(rep.skipped.len(), 1);
        let rep = restore(&mut db2, &mk2, "pw", &blob, true).unwrap();
        assert_eq!(rep.replaced.len(), 1);
    }
}
