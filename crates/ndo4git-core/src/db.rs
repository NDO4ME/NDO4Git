//! SQLite storage (WAL, `user_version` migrations, foreign keys on).

use crate::error::{Error, Result};
use crate::forge::Forge;
use crate::repo::DEFAULT_HOSTS;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row, TransactionBehavior};
use serde::Serialize;
use std::path::Path;
use std::time::Duration;

const MIGRATIONS: &[&str] = &[include_str!("../migrations/0001_init.sql")];

/// Update `last_used_at` at most once per this many seconds, to keep the hot
/// path from contending on the write lock.
const TOUCH_INTERVAL_SECS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Create the file if needed (management commands).
    Create,
    /// Open an existing file only (hot path).
    Existing,
}

pub struct Db {
    conn: Connection,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyRow {
    pub id: i64,
    pub repo: String,
    pub host: String,
    pub algo: String,
    pub public_key: String,
    pub fingerprint: String,
    #[serde(skip)]
    pub can_write: bool,
    pub created_at: i64,
    pub rotated_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

/// A key row together with its encrypted private part.
#[derive(Debug, Clone)]
pub struct SecretRow {
    pub row: KeyRow,
    pub private_key_enc: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryRow {
    pub public_key: String,
    pub fingerprint: String,
    pub can_write: bool,
    pub created_at: i64,
    pub retired_at: i64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AliasRow {
    pub alias: String,
    pub host: String,
    pub target: String,
    pub created_at: i64,
}

/// Everything needed to insert or replace a key.
pub struct NewKey<'a> {
    pub repo: &'a str,
    pub host: &'a str,
    pub algo: &'a str,
    pub public_key: &'a str,
    pub private_key_enc: &'a [u8],
    pub nonce: &'a [u8],
    pub fingerprint: &'a str,
    pub can_write: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

const KEY_COLS: &str = "id, repo, host, algo, public_key, fingerprint, can_write, created_at, rotated_at, last_used_at";

fn key_row(r: &Row<'_>) -> rusqlite::Result<KeyRow> {
    Ok(KeyRow {
        id: r.get(0)?,
        repo: r.get(1)?,
        host: r.get(2)?,
        algo: r.get(3)?,
        public_key: r.get(4)?,
        fingerprint: r.get(5)?,
        can_write: r.get::<_, i64>(6)? != 0,
        created_at: r.get(7)?,
        rotated_at: r.get(8)?,
        last_used_at: r.get(9)?,
    })
}

fn secret_row(r: &Row<'_>) -> rusqlite::Result<SecretRow> {
    Ok(SecretRow {
        row: key_row(r)?,
        private_key_enc: r.get(10)?,
        nonce: r.get(11)?,
    })
}

impl Db {
    pub fn open(path: &Path, mode: OpenMode, busy: Duration) -> Result<Self> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | if mode == OpenMode::Create {
                OpenFlags::SQLITE_OPEN_CREATE
            } else {
                OpenFlags::empty()
            };
        let conn = Connection::open_with_flags(path, flags)?;
        conn.busy_timeout(busy)?;
        if mode == OpenMode::Create {
            conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        }
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;")?;
        Ok(Self { conn })
    }

    /// Open for management commands: create + migrate to the latest schema.
    pub fn open_and_migrate(path: &Path) -> Result<Self> {
        let mut db = Self::open(path, OpenMode::Create, Duration::from_secs(5))?;
        db.migrate()?;
        Ok(db)
    }

    pub fn schema_version(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))?)
    }

    /// Apply pending migrations. Safe to run from several processes at once.
    pub fn migrate(&mut self) -> Result<()> {
        let current = usize::try_from(self.schema_version()?).unwrap_or(0);
        if current > MIGRATIONS.len() {
            return Err(Error::Invalid(format!(
                "database schema v{current} is newer than this ndo4git (v{}); upgrade ndo4git",
                MIGRATIONS.len()
            )));
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(current) {
            let tx = self
                .conn
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let v: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
            if usize::try_from(v).unwrap_or(0) > i {
                continue; // another process migrated while we waited for the lock
            }
            tx.execute_batch(sql)?;
            tx.execute_batch(&format!("PRAGMA user_version = {};", i + 1))?;
            tx.commit()?;
        }
        Ok(())
    }

    // ---------------------------------------------------------------- keys

    pub fn get_key(&self, repo: &str, host: &str) -> Result<Option<KeyRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {KEY_COLS} FROM keys WHERE repo = ?1 AND host = ?2"),
                params![repo, host],
                key_row,
            )
            .optional()?)
    }

    fn get_secret_exact(&self, repo: &str, host: &str) -> Result<Option<SecretRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {KEY_COLS}, private_key_enc, nonce FROM keys WHERE repo = ?1 AND host = ?2"),
                params![repo, host],
                secret_row,
            )
            .optional()?)
    }

    /// Look up the secret for `repo`, following one level of alias.
    pub fn resolve_secret(&self, repo: &str, host: &str) -> Result<Option<SecretRow>> {
        if let Some(s) = self.get_secret_exact(repo, host)? {
            return Ok(Some(s));
        }
        let target: Option<String> = self
            .conn
            .query_row(
                "SELECT target FROM aliases WHERE alias = ?1 AND host = ?2",
                params![repo, host],
                |r| r.get(0),
            )
            .optional()?;
        match target {
            Some(t) => self.get_secret_exact(&t, host),
            None => Ok(None),
        }
    }

    /// Like [`Db::resolve_secret`] but without the encrypted payload.
    pub fn resolve_key(&self, repo: &str, host: &str) -> Result<Option<KeyRow>> {
        Ok(self.resolve_secret(repo, host)?.map(|s| s.row))
    }

    /// Insert a new key. Fails with [`Error::KeyExists`] on a duplicate.
    pub fn insert_key(&mut self, k: &NewKey<'_>) -> Result<i64> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM keys WHERE repo = ?1 AND host = ?2)",
            params![k.repo, k.host],
            |r| r.get(0),
        )?;
        if exists {
            return Err(Error::KeyExists {
                repo: k.repo.into(),
                host: k.host.into(),
            });
        }
        tx.execute(
            "INSERT INTO keys (repo, host, algo, public_key, private_key_enc, nonce, fingerprint, can_write, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![k.repo, k.host, k.algo, k.public_key, k.private_key_enc, k.nonce, k.fingerprint, k.can_write, k.created_at, k.last_used_at],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Replace the key for `(repo, host)`, archiving the old public half in
    /// `key_history`. Inserts if there is no existing key.
    pub fn replace_key(&mut self, k: &NewKey<'_>, now: i64, reason: &str) -> Result<i64> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<(i64, String, String, String, bool, i64)> = tx
            .query_row(
                "SELECT id, algo, public_key, fingerprint, can_write, created_at FROM keys WHERE repo = ?1 AND host = ?2",
                params![k.repo, k.host],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, i64>(4)? != 0, r.get(5)?)),
            )
            .optional()?;
        let id = if let Some((id, algo, public_key, fp, can_write, created_at)) = old {
            tx.execute(
                "INSERT INTO key_history (key_id, repo, host, algo, public_key, fingerprint, can_write, created_at, retired_at, reason)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![id, k.repo, k.host, algo, public_key, fp, can_write, created_at, now, reason],
            )?;
            tx.execute(
                "UPDATE keys SET algo = ?2, public_key = ?3, private_key_enc = ?4, nonce = ?5, fingerprint = ?6,
                        can_write = ?7, created_at = ?8, rotated_at = ?9, last_used_at = NULL WHERE id = ?1",
                params![id, k.algo, k.public_key, k.private_key_enc, k.nonce, k.fingerprint, k.can_write, k.created_at, now],
            )?;
            id
        } else {
            tx.execute(
                "INSERT INTO keys (repo, host, algo, public_key, private_key_enc, nonce, fingerprint, can_write, created_at, last_used_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![k.repo, k.host, k.algo, k.public_key, k.private_key_enc, k.nonce, k.fingerprint, k.can_write, k.created_at, k.last_used_at],
            )?;
            tx.last_insert_rowid()
        };
        tx.commit()?;
        Ok(id)
    }

    pub fn list_keys(&self) -> Result<Vec<KeyRow>> {
        let mut st = self
            .conn
            .prepare(&format!("SELECT {KEY_COLS} FROM keys ORDER BY host, repo"))?;
        let rows = st
            .query_map([], key_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn all_secrets(&self) -> Result<Vec<SecretRow>> {
        let mut st = self.conn.prepare(&format!(
            "SELECT {KEY_COLS}, private_key_enc, nonce FROM keys ORDER BY host, repo"
        ))?;
        let rows = st
            .query_map([], secret_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn history(&self, key_id: i64) -> Result<Vec<HistoryRow>> {
        let mut st = self.conn.prepare(
            "SELECT public_key, fingerprint, can_write, created_at, retired_at, reason
             FROM key_history WHERE key_id = ?1 ORDER BY retired_at DESC, id DESC",
        )?;
        let rows = st
            .query_map([key_id], |r| {
                Ok(HistoryRow {
                    public_key: r.get(0)?,
                    fingerprint: r.get(1)?,
                    can_write: r.get::<_, i64>(2)? != 0,
                    created_at: r.get(3)?,
                    retired_at: r.get(4)?,
                    reason: r.get(5)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Delete a key (history cascades) and any aliases pointing at it.
    pub fn delete_key(&mut self, repo: &str, host: &str) -> Result<bool> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM aliases WHERE target = ?1 AND host = ?2",
            params![repo, host],
        )?;
        let n = tx.execute(
            "DELETE FROM keys WHERE repo = ?1 AND host = ?2",
            params![repo, host],
        )?;
        tx.commit()?;
        Ok(n > 0)
    }

    /// Best-effort `last_used_at` update (rate limited).
    pub fn touch(&self, id: i64, now: i64) -> Result<()> {
        self.conn.execute(
            "UPDATE keys SET last_used_at = ?2 WHERE id = ?1 AND (last_used_at IS NULL OR last_used_at < ?3)",
            params![id, now, now - TOUCH_INTERVAL_SECS],
        )?;
        Ok(())
    }

    // ---------------------------------------------------------------- aliases

    /// Make requests for `alias` use the key of `target`.
    pub fn add_alias(&mut self, alias: &str, target: &str, host: &str, now: i64) -> Result<()> {
        if alias == target {
            return Err(Error::Invalid(
                "alias and target are the same repository".into(),
            ));
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let has = |repo: &str| -> rusqlite::Result<bool> {
            tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM keys WHERE repo = ?1 AND host = ?2)",
                params![repo, host],
                |r| r.get(0),
            )
        };
        if !has(target)? {
            return Err(Error::NotFound {
                repo: target.into(),
                host: host.into(),
            });
        }
        if has(alias)? {
            return Err(Error::Invalid(format!(
                "{alias} has its own key on {host}; remove it first or the alias would never apply"
            )));
        }
        tx.execute(
            "INSERT INTO aliases (alias, host, target, created_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(alias, host) DO UPDATE SET target = excluded.target, created_at = excluded.created_at",
            params![alias, host, target, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_alias(&mut self, alias: &str, host: &str) -> Result<bool> {
        let n = self.conn.execute(
            "DELETE FROM aliases WHERE alias = ?1 AND host = ?2",
            params![alias, host],
        )?;
        Ok(n > 0)
    }

    pub fn list_aliases(&self) -> Result<Vec<AliasRow>> {
        let mut st = self
            .conn
            .prepare("SELECT alias, host, target, created_at FROM aliases ORDER BY host, alias")?;
        let rows = st
            .query_map([], |r| {
                Ok(AliasRow {
                    alias: r.get(0)?,
                    host: r.get(1)?,
                    target: r.get(2)?,
                    created_at: r.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    // ---------------------------------------------------------------- meta / hosts

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Hosts for which the wrapper selects keys (default: GitHub, Codeberg, GitLab).
    pub fn hosts(&self) -> Result<Vec<String>> {
        Ok(match self.get_meta("hosts")? {
            Some(v) => v
                .split(',')
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .map(str::to_owned)
                .collect(),
            None => DEFAULT_HOSTS.iter().map(|h| (*h).to_owned()).collect(),
        })
    }

    pub fn set_hosts(&self, hosts: &[String]) -> Result<()> {
        self.set_meta("hosts", &hosts.join(","))
    }

    /// Forge software of `host`: explicit override, else guessed from the name.
    /// Host-key handling for managed calls (meta `hostkey_policy`).
    pub fn hostkey_policy(&self) -> Result<crate::exec::HostKeyPolicy> {
        Ok(self
            .get_meta("hostkey_policy")?
            .and_then(|v| crate::exec::HostKeyPolicy::parse(&v))
            .unwrap_or_default())
    }

    pub fn set_hostkey_policy(&self, p: crate::exec::HostKeyPolicy) -> Result<()> {
        self.set_meta("hostkey_policy", p.name())
    }

    pub fn forge(&self, host: &str) -> Result<Forge> {
        Ok(self
            .get_meta(&format!("forge:{host}"))?
            .and_then(|v| Forge::parse(&v))
            .unwrap_or_else(|| Forge::detect(host)))
    }

    pub fn set_forge(&self, host: &str, forge: Forge) -> Result<()> {
        self.set_meta(&format!("forge:{host}"), forge.name())
    }

    // ---------------------------------------------------------------- health

    /// `PRAGMA integrity_check`; returns the problems (empty when healthy).
    pub fn integrity_check(&self) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("PRAGMA integrity_check")?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows.into_iter().filter(|l| l != "ok").collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem() -> Db {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("k.db");
        let db = Db::open_and_migrate(&p).unwrap();
        std::mem::forget(t); // keep dir alive for the test's lifetime
        db
    }

    fn nk<'a>(repo: &'a str, host: &'a str, fp: &'a str) -> NewKey<'a> {
        NewKey {
            repo,
            host,
            algo: "ssh-ed25519",
            public_key: "ssh-ed25519 AAAA",
            private_key_enc: b"enc",
            nonce: b"nonce",
            fingerprint: fp,
            can_write: true,
            created_at: 100,
            last_used_at: None,
        }
    }

    #[test]
    fn migrate_is_idempotent() {
        let mut db = mem();
        assert_eq!(db.schema_version().unwrap(), 1);
        db.migrate().unwrap();
        assert_eq!(db.schema_version().unwrap(), 1);
        assert!(db.integrity_check().unwrap().is_empty());
    }

    #[test]
    fn insert_get_duplicate_delete() {
        let mut db = mem();
        db.insert_key(&nk("o/r", "github.com", "SHA256:a")).unwrap();
        assert!(matches!(
            db.insert_key(&nk("o/r", "github.com", "SHA256:b")),
            Err(Error::KeyExists { .. })
        ));
        db.insert_key(&nk("o/r", "ghe.example.com", "SHA256:c"))
            .unwrap();
        let k = db.get_key("o/r", "github.com").unwrap().unwrap();
        assert_eq!(k.fingerprint, "SHA256:a");
        assert!(k.can_write);
        assert_eq!(db.list_keys().unwrap().len(), 2);
        assert!(db.delete_key("o/r", "github.com").unwrap());
        assert!(!db.delete_key("o/r", "github.com").unwrap());
        assert!(db.get_key("o/r", "github.com").unwrap().is_none());
    }

    #[test]
    fn replace_keeps_history() {
        let mut db = mem();
        let id = db.insert_key(&nk("o/r", "github.com", "SHA256:a")).unwrap();
        let id2 = db
            .replace_key(&nk("o/r", "github.com", "SHA256:b"), 200, "rotate")
            .unwrap();
        assert_eq!(id, id2);
        let k = db.get_key("o/r", "github.com").unwrap().unwrap();
        assert_eq!(
            (k.fingerprint.as_str(), k.rotated_at),
            ("SHA256:b", Some(200))
        );
        let h = db.history(id).unwrap();
        assert_eq!(h.len(), 1);
        assert_eq!(
            (
                h[0].fingerprint.as_str(),
                h[0].retired_at,
                h[0].reason.as_str()
            ),
            ("SHA256:a", 200, "rotate")
        );
        // replace on a missing key inserts
        db.replace_key(&nk("x/y", "github.com", "SHA256:z"), 300, "rotate")
            .unwrap();
        assert!(db.get_key("x/y", "github.com").unwrap().is_some());
        // deleting cascades history
        db.delete_key("o/r", "github.com").unwrap();
        assert!(db.history(id).unwrap().is_empty());
    }

    #[test]
    fn aliases_resolve_and_validate() {
        let mut db = mem();
        db.insert_key(&nk("new/name", "github.com", "SHA256:a"))
            .unwrap();
        db.add_alias("old/name", "new/name", "github.com", 1)
            .unwrap();
        let s = db
            .resolve_secret("old/name", "github.com")
            .unwrap()
            .unwrap();
        assert_eq!(s.row.repo, "new/name");
        assert!(db
            .resolve_secret("old/name", "other.host")
            .unwrap()
            .is_none());
        assert!(db.add_alias("a/b", "missing/x", "github.com", 1).is_err());
        assert!(db
            .add_alias("new/name", "new/name", "github.com", 1)
            .is_err());
        db.insert_key(&nk("own/key", "github.com", "SHA256:b"))
            .unwrap();
        assert!(db
            .add_alias("own/key", "new/name", "github.com", 1)
            .is_err());
        assert_eq!(db.list_aliases().unwrap().len(), 1);
        db.delete_key("new/name", "github.com").unwrap();
        assert!(db.list_aliases().unwrap().is_empty());
    }

    #[test]
    fn touch_is_rate_limited() {
        let mut db = mem();
        let id = db.insert_key(&nk("o/r", "github.com", "SHA256:a")).unwrap();
        db.touch(id, 1000).unwrap();
        assert_eq!(
            db.get_key("o/r", "github.com")
                .unwrap()
                .unwrap()
                .last_used_at,
            Some(1000)
        );
        db.touch(id, 1010).unwrap();
        assert_eq!(
            db.get_key("o/r", "github.com")
                .unwrap()
                .unwrap()
                .last_used_at,
            Some(1000)
        );
        db.touch(id, 1100).unwrap();
        assert_eq!(
            db.get_key("o/r", "github.com")
                .unwrap()
                .unwrap()
                .last_used_at,
            Some(1100)
        );
    }

    #[test]
    fn hosts_default_and_set() {
        let db = mem();
        assert_eq!(
            db.hosts().unwrap(),
            ["github.com", "codeberg.org", "gitlab.com"]
        );
        db.set_hosts(&["github.com".into(), "ghe.example.com".into()])
            .unwrap();
        assert_eq!(db.hosts().unwrap(), ["github.com", "ghe.example.com"]);
    }

    #[test]
    fn forge_override() {
        let db = mem();
        assert_eq!(db.forge("codeberg.org").unwrap(), Forge::Forgejo);
        assert_eq!(db.forge("git.example.org").unwrap(), Forge::GitHub);
        db.set_forge("git.example.org", Forge::GitLab).unwrap();
        assert_eq!(db.forge("git.example.org").unwrap(), Forge::GitLab);
    }

    #[test]
    fn existing_mode_does_not_create() {
        let t = tempfile::tempdir().unwrap();
        assert!(Db::open(
            &t.path().join("none.db"),
            OpenMode::Existing,
            Duration::from_millis(50)
        )
        .is_err());
    }
}
