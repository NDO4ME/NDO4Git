# Changelog

## 0.4.0

### Added
* Manifest (`manifest.toml`) with `init`, `plan [--check]`, `apply` and `rollback`: managed hosts,
  keys, aliases, host-key policy, per-repository git identities (`includeIf`, SSH commit signing)
  and an allow-listed `[settings]` table. A `perf` preset removes the `ssh -G` probe and enables
  parallel fetch, commit-graph and other daemon-free speedups.
* `whoami`: which identity applies to a repository and whether git really uses it.
* `git` shim: `install` links `/usr/local/bin/git` to ndo4git, which `exec`s the real git.
  `install` refuses to run when git is not installed.
* `schema` command and `--json` on `plan`, `apply`, `rollback`, `whoami` and `host list`.

### Hardened
* `rollback` validates the journal (include path, host and repo names, derived file names) before touching anything, never deletes a key that has been used, and reports what it kept.
* `apply` and `rollback` take an exclusive lock.
* The `git` shim falls back to well-known git locations and has a recursion guard.
* `whoami` merges all matching identities exactly as git does.
* `apply` and `rollback` refuse to run as root, so a root-owned include can never end up in a user's `~/.gitconfig`.
* Managed ssh calls disable connection multiplexing (`ControlMaster=no`, `ControlPath=none`), so a connection opened with another repository's key is never reused.
* Identity patterns now match nested GitLab groups (`**` spans `/`) and `ssh://host:PORT/` URLs.
* `identities` check for git 2.36+ (`includeIf hasconfig`) and fail with a clear message otherwise; removing the include no longer needs `--fixed-value` (git 2.30+).
* `--purge` only removes a data directory owned by the user it belongs to and reached without symlinks.

### CI
* `.github/workflows/ci.yml`: fmt, clippy and tests and cross-builds all four targets in one job on one Ubuntu 22.04 VM (zig as linker). Tests run on Linux only.
* `.github/workflows/release.yml`: one job on one VM: tests, four binaries (static musl for Linux x86_64/aarch64, macOS x86_64/aarch64) and two `.deb` packages, version check against `Cargo.toml`, leak check on the binaries, smoke tests on Alpine, Debian, Ubuntu and Fedora, `SHA256SUMS` and a GitHub release.

### Known limitations
* `--sudo-user-home` ownership checks are not reliable yet; run ndo4git as your own user.
* macOS and aarch64 are built from the same code but not yet tested on real hardware.

### Removed
* `scripts/release.sh` (local cross-build and Codeberg upload): releases are built by the GitHub release workflow, with checksums instead of a local signing key.
* The `write` flag, column and field (deploy-key write access is no longer tracked).
* `doctor` and `update` (self-update, release-signature verification, the HTTP client).
* `uninstall` as a public command (kept hidden for the `.deb` removal script).
* Windows support (PowerShell completions, any non-Unix build).

## 0.3.0
* Self-update, multi-forge support, key hand-off fix; macOS and aarch64 builds, `.deb` packages,
  host-key policy.
