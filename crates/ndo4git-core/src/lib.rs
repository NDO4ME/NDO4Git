//! Core library for `ndo4git`.
//!
//! Module map:
//! * [`forge`]   – GitHub / Forgejo (Codeberg) / GitLab differences
//! * [`repo`]    – the single repo-name normaliser, git remote URL parsing
//! * [`wrapper`] – pure parsing of the argv git hands to `core.sshCommand`
//! * [`gitshim`] – the `git` symlink: exec the real git, skipping ourselves
//! * [`exec`]    – the hot path: key lookup, memfd key hand-off, `exec` of real ssh
//! * [`db`]      – SQLite storage and migrations
//! * [`crypto`]  – master key, XChaCha20-Poly1305 sealing, passphrase blobs
//! * [`manifest`] – the declarative TOML manifest (single source of truth)
//! * [`plan`]    – plan / apply / rollback against the manifest
//! * [`keygen`]  – in-process ed25519 key generation / import
//! * [`backup`]  – encrypted export / import of the whole database
//! * [`install`] – system-wide install / uninstall (root)
//! * [`paths`], [`util`], [`error`] – plumbing
#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::assert_is_empty)
)]

#[cfg(not(unix))]
compile_error!("ndo4git supports Linux and macOS only");

pub mod backup;
pub mod crypto;
pub mod db;
pub mod error;
pub mod exec;
pub mod forge;
pub mod gitshim;
pub mod install;
pub mod keygen;
pub mod manifest;
pub mod paths;
pub mod plan;
pub mod repo;
pub mod util;
pub mod wrapper;

pub use error::{Error, Result};
