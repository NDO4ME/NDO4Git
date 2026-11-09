//! Error type shared by the whole workspace.

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: io::Error,
    },
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("ssh key error: {0}")]
    SshKey(#[from] ssh_key::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("a key for {repo} on {host} already exists")]
    KeyExists { repo: String, host: String },
    #[error("no key for {repo} on {host}")]
    NotFound { repo: String, host: String },
    #[error("cannot determine the home directory (no passwd entry and $HOME unset)")]
    NoHome,
    #[error("{0}")]
    Insecure(String),
    #[error("system error: {0}")]
    Nix(#[from] nix::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Attach a human-readable context to an `io::Result`.
pub trait IoContext<T> {
    fn ctx(self, context: impl Into<String>) -> Result<T>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn ctx(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|source| Error::Io {
            context: context.into(),
            source,
        })
    }
}
