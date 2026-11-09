//! Diagnostics behind `ndo4git doctor`.

use crate::db::{Db, OpenMode};
use crate::exec::find_ssh;
use crate::install::{git_config_get, Plan};
use crate::paths;
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub status: Status,
    pub name: &'static str,
    pub detail: String,
}

fn check(status: Status, name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        status,
        name,
        detail: detail.into(),
    }
}

/// Run every check. `sudo_user_home` selects the data directory like the other commands.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(plan: &Plan, sudo_user_home: bool) -> Vec<Check> {
    let mut out = Vec::new();
    let expected = plan.ssh_command();

    // 1. system install present
    let bin = plan.bin_path();
    let bin_ok = std::fs::metadata(&bin).is_ok_and(|m| m.is_file());
    let link_ok = std::fs::read_link(plan.link_path()).is_ok();
    out.push(match (bin_ok, link_ok) {
        (true, true) => check(
            Status::Ok,
            "system install",
            format!("{} and git-ndo4git present", bin.display()),
        ),
        (true, false) => check(
            Status::Warn,
            "system install",
            format!(
                "{} missing (`git ndo4git` will not work)",
                plan.link_path().display()
            ),
        ),
        _ => check(
            Status::Fail,
            "system install",
            format!("{} not found; run: sudo ndo4git install", bin.display()),
        ),
    });

    // 2. /etc/gitconfig
    out.push(match plan.config_get("--system") {
        Ok(Some(v)) if v == expected => check(Status::Ok, "system core.sshCommand", v),
        Ok(Some(v)) => check(
            Status::Fail,
            "system core.sshCommand",
            format!("is {v:?}, expected {expected:?}"),
        ),
        Ok(None) => check(
            Status::Fail,
            "system core.sshCommand",
            "not set; run: sudo ndo4git install",
        ),
        Err(e) => check(Status::Fail, "system core.sshCommand", e.to_string()),
    });

    // 3. real ssh
    out.push(match find_ssh() {
        Some(p) => check(Status::Ok, "real ssh", p.display().to_string()),
        None => check(
            Status::Fail,
            "real ssh",
            "no ssh found in PATH (install openssh-client or set NDO4GIT_SSH)",
        ),
    });

    // 4/5. data dir, database
    match paths::config_dir(sudo_user_home) {
        Err(e) => out.push(check(Status::Fail, "data directory", e.to_string())),
        Ok(dir) if !dir.exists() => out.push(check(
            Status::Ok,
            "data directory",
            format!(
                "{} does not exist yet (created by `ndo4git new`)",
                dir.display()
            ),
        )),
        Ok(dir) => {
            out.push(match paths::check_perms(&dir, false) {
                Ok(p) if p.is_empty() => check(
                    Status::Ok,
                    "permissions",
                    format!("{} is private", dir.display()),
                ),
                Ok(p) => check(
                    Status::Warn,
                    "permissions",
                    format!("{} (any ndo4git command repairs this)", p.join("; ")),
                ),
                Err(e) => check(Status::Fail, "permissions", e.to_string()),
            });
            let db_path = paths::db_path(&dir);
            if db_path.exists() {
                out.push(
                    match Db::open(&db_path, OpenMode::Existing, Duration::from_secs(2)) {
                        Err(e) => check(Status::Fail, "database", e.to_string()),
                        Ok(db) => match db.integrity_check() {
                            Ok(p) if p.is_empty() => {
                                let n = db.list_keys().map_or(0, |k| k.len());
                                let v = db.schema_version().unwrap_or(-1);
                                check(
                                    Status::Ok,
                                    "database",
                                    format!("integrity ok, schema v{v}, {n} key(s)"),
                                )
                            }
                            Ok(p) => check(
                                Status::Fail,
                                "database",
                                format!("integrity_check: {}", p.join("; ")),
                            ),
                            Err(e) => check(Status::Fail, "database", e.to_string()),
                        },
                    },
                );
                if !dir.join(paths::MASTER_KEY_FILE).exists() {
                    out.push(check(
                        Status::Fail,
                        "master key",
                        "master.key is missing; stored keys cannot be decrypted",
                    ));
                }
            } else {
                out.push(check(Status::Ok, "database", "no database yet"));
            }
        }
    }

    // 6. overrides that shadow the system setting
    let mut overridden = false;
    for (scope, label) in [
        ("--global", "global git config"),
        ("--local", "repository git config"),
    ] {
        if let Ok(Some(v)) = git_config_get(scope, &plan.git_env) {
            overridden = true;
            let detail = if v == expected {
                check(
                    Status::Ok,
                    "override",
                    format!("{label} sets core.sshCommand to the same wrapper"),
                )
            } else {
                check(Status::Warn, "override", format!("{label} defines core.sshCommand = {v:?}; it overrides the system setting, so ndo4git is bypassed here"))
            };
            out.push(detail);
        }
    }
    if let Some(v) = std::env::var_os("GIT_SSH_COMMAND").filter(|v| !v.is_empty()) {
        overridden = true;
        out.push(check(
            Status::Warn,
            "override",
            format!("GIT_SSH_COMMAND is set ({v:?}); it takes precedence over core.sshCommand"),
        ));
    }
    if !overridden {
        out.push(check(
            Status::Ok,
            "overrides",
            "no global/local core.sshCommand or GIT_SSH_COMMAND",
        ));
    }
    out
}
