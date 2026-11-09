//! `ndo4git` binary: thin CLI over `ndo4git-core`.
#![forbid(unsafe_code)]

mod cli;
mod commands;
mod prompt;
mod render;

use std::ffi::OsString;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _argv0 = args.next();
    let first = args.next();

    // Hot path: git invokes `ndo4git ssh-wrapper <ssh args...>`. Handle it
    // before clap is even constructed so startup stays minimal.
    if first.as_deref() == Some(std::ffi::OsStr::new("ssh-wrapper")) {
        let rest: Vec<OsString> = args.collect();
        let code = ndo4git_core::exec::run_wrapper(rest);
        return ExitCode::from(u8::try_from(code).unwrap_or(1));
    }

    // Internal helper that holds the decrypted key for ssh (see `exec` docs).
    if first.as_deref() == Some(std::ffi::OsStr::new(ndo4git_core::exec::HOLDER_ARG)) {
        return ExitCode::from(u8::try_from(ndo4git_core::exec::run_key_holder()).unwrap_or(1));
    }

    // `git-ndo4git` symlink: behave identically (git passes subcommand args).
    match commands::run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ndo4git: error: {e:#}");
            ExitCode::from(1)
        }
    }
}
