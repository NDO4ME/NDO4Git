//! clap definitions.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ndo4git",
    version,
    about = "Transparent per-repository SSH keys for git over SSH (GitHub, Codeberg/Forgejo, GitLab)",
    long_about = "ndo4git picks a dedicated SSH key per repository whenever the system \
git talks to GitHub, Codeberg (Forgejo) or GitLab over SSH, and manages those keys in a local, encrypted SQLite database.\n\n\
Install once (as root) with `sudo ndo4git install`; afterwards git push/pull/fetch/clone work unchanged."
)]
pub struct Cli {
    /// Host the repository lives on (default: github.com; ignored when a URL is given)
    #[arg(long, global = true, value_name = "HOST")]
    pub host: Option<String>,

    /// When running as root under sudo, use `$SUDO_USER`'s data directory
    #[arg(long, global = true)]
    pub sudo_user_home: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate a new key for a repository and print the public half
    New {
        /// OWNER/REPO, GROUP/SUB/PROJECT, HOST/PATH or a clone URL (default: `origin` of the current directory)
        target: Option<String>,
        /// Replace an existing key (the old public key is kept in history)
        #[arg(long)]
        rotate: bool,
        /// Record that the deploy key should have write access
        #[arg(long)]
        write: bool,
        /// Public key comment (default: ndo4git:OWNER/REPO@HOSTNAME)
        #[arg(long, value_name = "STR")]
        comment: Option<String>,
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Internal: invoked by git as core.sshCommand
    #[command(hide = true, name = "ssh-wrapper")]
    SshWrapper {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<String>,
    },
    /// List stored keys
    List {
        #[arg(long)]
        json: bool,
    },
    /// Show one key, its history and aliases
    Show {
        repo: String,
        #[arg(long)]
        json: bool,
    },
    /// Delete a key
    Rm { repo: String },
    /// Import an existing unencrypted OpenSSH private key (FILE or `-` for stdin)
    Import {
        repo: String,
        file: PathBuf,
        /// Replace an existing key
        #[arg(long)]
        force: bool,
        #[arg(long)]
        write: bool,
        #[arg(long, value_name = "STR")]
        comment: Option<String>,
    },
    /// Print the public key
    ExportPub { repo: String },
    /// Print the PRIVATE key (requires --yes)
    ExportPrivate {
        repo: String,
        #[arg(long)]
        yes: bool,
    },
    /// Make OLD (e.g. a renamed/transferred repo) use the key of NEW
    Alias {
        old: String,
        new: String,
        /// Remove the alias instead
        #[arg(long)]
        remove: bool,
    },
    /// Manage the hosts the wrapper acts on (defaults: github.com, codeberg.org, gitlab.com)
    Host {
        #[command(subcommand)]
        action: HostAction,
    },
    /// Check installation, configuration, permissions and database health
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Write an encrypted backup of all keys
    Backup {
        file: PathBuf,
        /// Overwrite FILE if it exists
        #[arg(long)]
        force: bool,
        /// Read the passphrase from this file (else `$NDO4GIT_BACKUP_PASSPHRASE`, else prompt)
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
    /// Restore keys from an encrypted backup
    Restore {
        file: PathBuf,
        /// Replace keys that already exist
        #[arg(long)]
        overwrite: bool,
        #[arg(long, value_name = "FILE")]
        passphrase_file: Option<PathBuf>,
    },
    /// Install system-wide (root): binary, git-ndo4git link, /etc/gitconfig
    Install,
    /// Reverse `install` (root); user data is kept unless --purge
    Uninstall {
        /// Also delete every user's ~/.config/ndo4git
        #[arg(long)]
        purge: bool,
    },
    /// Print a shell completion script
    Completions { shell: Shell },
    /// Print the man page (roff)
    Man,
}

#[derive(Subcommand, Debug)]
pub enum HostAction {
    /// Show managed hosts
    List,
    /// Manage keys for HOST too
    Add {
        host: String,
        /// Forge software: github, gitlab or forgejo (default: guessed from the name)
        #[arg(long, value_name = "KIND")]
        forge: Option<String>,
    },
    /// Stop managing HOST
    Rm { host: String },
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    Elvish,
    Powershell,
}
