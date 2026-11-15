# Working on ndo4git

Notes for anyone (people or automation tools) changing or driving this repository.

## Build and check

```sh
cargo fmt --all && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace
```

All three must pass. CI (`.github/workflows/ci.yml`) runs the same checks on Linux and macOS; still run them before every commit.

## Rules of the project

* **The hot path stays untouched.** `ndo4git ssh-wrapper` (`exec.rs`, `wrapper.rs`) must not gain
  work, dependencies or allocations. `main()` handles `ssh-wrapper`, the key holder and the `git`
  shim before clap is built.
* **Lean.** No new dependency without a measured reason. Release size, startup time, memory and
  disk use matter more than features. No HTTP client in the binary.
* **No `unsafe`** (`#![forbid(unsafe_code)]`), no `unwrap`/`expect` outside tests.
* **Linux and macOS only.** No Windows code paths.
* **Fail open** in the wrapper; **fail closed** in everything that writes (manifest, install).
* **One validator** for repository names (`repo::normalize_repo`) and one for manifest values
  (`manifest.rs`). Never build a shell string; use argv arrays.
* **No attribution lines** from tools or assistants in commits, code or docs.

## Driving the CLI from a script or an agent

* `ndo4git schema` prints every command, option, exit code and environment variable as JSON,
  generated from the real clap definitions.
* Commands with `--json` write JSON to stdout only. Errors and hints go to stderr.
* Exit codes: `0` ok, `1` error, `2` key exists (`new`) or changes pending (`plan --check`).
* `plan` is read-only and `apply` is idempotent; `rollback` undoes the last `apply`.
* Nothing prompts unless a backup passphrase is required; set `NDO4GIT_BACKUP_PASSPHRASE` or pass
  `--passphrase-file` to stay non-interactive.
* Use `--manifest FILE` / `NDO4GIT_MANIFEST` and `XDG_CONFIG_HOME` to work in an isolated
  directory (the integration tests do exactly this).

## Layout

See the Architecture section of `README.md`. Pure logic lives in `ndo4git-core` with unit tests;
`ndo4git` is the thin CLI; `crates/ndo4git/tests/integration.rs` runs the real binary.
