//! Passphrase input (no echo on a TTY).

use anyhow::{bail, Context, Result};
use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};
use std::fs;
use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use zeroize::Zeroizing;

fn read_line_hidden(prompt: &str) -> Result<Zeroizing<String>> {
    let stdin = std::io::stdin();
    let mut line = Zeroizing::new(String::new());
    if stdin.is_terminal() {
        eprint!("{prompt}");
        std::io::stderr().flush().ok();
        let orig = tcgetattr(&stdin).context("reading terminal settings")?;
        let mut quiet = orig.clone();
        quiet.local_flags.remove(LocalFlags::ECHO);
        tcsetattr(&stdin, SetArg::TCSAFLUSH, &quiet).context("disabling echo")?;
        let res = stdin.lock().read_line(&mut line);
        let _ = tcsetattr(&stdin, SetArg::TCSAFLUSH, &orig);
        eprintln!();
        res.context("reading passphrase")?;
    } else {
        stdin
            .lock()
            .read_line(&mut line)
            .context("reading passphrase from stdin")?;
    }
    while line.ends_with(['\n', '\r']) {
        line.pop();
    }
    Ok(line)
}

/// Passphrase from file, `$NDO4GIT_BACKUP_PASSPHRASE`, or an interactive prompt.
pub fn passphrase(file: Option<&Path>, confirm: bool) -> Result<Zeroizing<String>> {
    let pw = if let Some(f) = file {
        let mut s = Zeroizing::new(
            fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?,
        );
        while s.ends_with(['\n', '\r']) {
            s.pop();
        }
        s
    } else if let Some(v) = std::env::var("NDO4GIT_BACKUP_PASSPHRASE")
        .ok()
        .filter(|v| !v.is_empty())
    {
        Zeroizing::new(v)
    } else {
        let p = read_line_hidden("Backup passphrase: ")?;
        if confirm {
            let again = read_line_hidden("Repeat passphrase: ")?;
            if *p != *again {
                bail!("passphrases do not match");
            }
        }
        p
    };
    if pw.is_empty() {
        bail!("empty passphrase");
    }
    Ok(pw)
}
