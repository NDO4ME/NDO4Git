//! `ndo4git update`: self-update from Codeberg releases.
//!
//! Flow: query the Forgejo releases API → pick the asset for this CPU →
//! download it and its `.sha256` → verify → stage next to the running binary →
//! run the staged binary with `--version` as a smoke test → atomic rename.
//!
//! Trust model: TLS to codeberg.org plus a SHA-256 published beside the asset.
//! This catches corruption and truncated downloads; it does not protect against
//! a compromised release (there is no separate signing key).

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

/// Releases API of the project. `NDO4GIT_RELEASES_API` overrides it (mirrors, tests).
const DEFAULT_API: &str = "https://codeberg.org/api/v1/repos/NDO4ME/git/releases";
const MAX_ASSET_BYTES: u64 = 64 * 1024 * 1024;
const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

/// `v1.2.3` / `1.2.3` → `(1, 2, 3)`. Pre-release tags (`1.2.3-rc1`) are rejected.
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches('v');
    let mut it = s.split('.');
    let v = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    it.next().is_none().then_some(v)
}

/// Name of the release asset for this CPU.
pub fn asset_name(arch: &str) -> String {
    format!("ndo4git-{arch}-linux-musl")
}

fn select<'a>(r: &'a ApiRelease, arch: &str) -> Result<(&'a str, Option<&'a str>)> {
    let want = asset_name(arch);
    let bin = r
        .assets
        .iter()
        .find(|a| a.name == want)
        .ok_or_else(|| anyhow!("release {} has no asset named {want}", r.tag_name))?;
    let sha = r
        .assets
        .iter()
        .find(|a| a.name == format!("{want}.sha256"))
        .map(|a| a.browser_download_url.as_str());
    Ok((bin.browser_download_url.as_str(), sha))
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::new(), |s, b| s + &format!("{b:02x}"))
}

/// Check `data` against a checksum file (`<hex>` or `<hex>  <name>`).
pub fn verify_sha256(data: &[u8], checksum_file: &str, asset: &str) -> Result<()> {
    let line = checksum_file
        .lines()
        .find(|l| {
            l.split_whitespace()
                .nth(1)
                .is_none_or(|n| n.trim_start_matches('*') == asset)
        })
        .ok_or_else(|| anyhow!("checksum file has no entry for {asset}"))?;
    let want = line
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let got = hex(&Sha256::digest(data));
    if want != got {
        bail!("checksum mismatch for {asset}: expected {want}, got {got}");
    }
    Ok(())
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .user_agent(format!("ndo4git/{CURRENT}"))
        .build()
        .into()
}

fn get_bytes(agent: &ureq::Agent, url: &str, limit: u64) -> Result<Vec<u8>> {
    let mut resp = agent
        .get(url)
        .call()
        .with_context(|| format!("GET {url}"))?;
    resp.body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .with_context(|| format!("reading {url}"))
}

fn fetch_release(agent: &ureq::Agent, version: Option<&str>) -> Result<ApiRelease> {
    let base = std::env::var("NDO4GIT_RELEASES_API").unwrap_or_else(|_| DEFAULT_API.to_owned());
    let url = match version {
        Some(v) => format!("{base}/tags/v{}", v.trim_start_matches('v')),
        None => format!("{base}/latest"),
    };
    let body = match agent.get(&url).call() {
        Ok(mut r) => r
            .body_mut()
            .read_to_vec()
            .with_context(|| format!("reading {url}"))?,
        Err(ureq::Error::StatusCode(404)) => {
            bail!("no matching release has been published yet ({url})")
        }
        Err(e) => return Err(e).with_context(|| format!("GET {url}")),
    };
    let r: ApiRelease = serde_json::from_slice(&body).context("unexpected releases API reply")?;
    if r.draft || (r.prerelease && version.is_none()) {
        bail!(
            "latest release {} is a draft/pre-release; use --version to select it",
            r.tag_name
        );
    }
    Ok(r)
}

/// Stage `data` next to `exe`, smoke-test it, and atomically rename it into place.
fn replace_binary(exe: &Path, data: &[u8], expect_version: &str) -> Result<()> {
    let staging = exe.with_file_name(format!(".ndo4git-update.{}", std::process::id()));
    let _ = fs::remove_file(&staging);
    let res = (|| -> Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o755)
            .open(&staging)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    anyhow!(
                        "cannot write to {}: permission denied (try: sudo ndo4git update)",
                        exe.parent().unwrap_or(exe).display()
                    )
                } else {
                    anyhow!(e).context(format!("creating {}", staging.display()))
                }
            })?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        let out = std::process::Command::new(&staging)
            .arg("--version")
            .output()
            .context("running the downloaded binary")?;
        let said = String::from_utf8_lossy(&out.stdout);
        if !out.status.success() || !said.contains(expect_version) {
            bail!(
                "downloaded binary failed its self-test (got {:?}); not installing",
                said.trim()
            );
        }
        fs::rename(&staging, exe).with_context(|| format!("replacing {}", exe.display()))?;
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&staging);
    }
    res
}

pub fn run(check: bool, version: Option<&str>, force: bool) -> Result<ExitCode> {
    let agent = agent();
    let release = fetch_release(&agent, version)?;
    let latest = parse_version(&release.tag_name)
        .ok_or_else(|| anyhow!("cannot parse release tag {:?}", release.tag_name))?;
    let current =
        parse_version(CURRENT).ok_or_else(|| anyhow!("bad built-in version {CURRENT}"))?;
    let latest_str = format!("{}.{}.{}", latest.0, latest.1, latest.2);

    if latest == current && !force {
        println!("ndo4git {CURRENT} is up to date");
        return Ok(ExitCode::SUCCESS);
    }
    if latest < current && !force && version.is_none() {
        println!("ndo4git {CURRENT} is newer than the latest release ({latest_str})");
        return Ok(ExitCode::SUCCESS);
    }
    if check {
        println!("update available: {CURRENT} -> {latest_str}");
        return Ok(ExitCode::SUCCESS);
    }

    let arch = std::env::consts::ARCH;
    let (bin_url, sha_url) = select(&release, arch)?;
    let name = asset_name(arch);
    let sha_url = sha_url.ok_or_else(|| {
        anyhow!("release has no {name}.sha256; refusing to install unverified code")
    })?;

    eprintln!("downloading {name} {latest_str} ...");
    let data = get_bytes(&agent, bin_url, MAX_ASSET_BYTES)?;
    let sums = String::from_utf8(get_bytes(&agent, sha_url, 64 * 1024)?)
        .context("checksum file is not UTF-8")?;
    verify_sha256(&data, &sums, &name)?;

    let exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .context("locating the running executable")?;
    replace_binary(&exe, &data, &latest_str)?;
    println!("updated {} : {CURRENT} -> {latest_str}", exe.display());

    let system = ndo4git_core::install::Plan::system()?.bin_path();
    if fs::canonicalize(&system).is_ok_and(|s| s != exe) {
        println!(
            "note: the system-wide wrapper {} was not changed; run: sudo ndo4git install",
            system.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.10.0"), Some((0, 10, 0)));
        assert!(parse_version("v1.2").is_none());
        assert!(parse_version("v1.2.3-rc1").is_none());
        assert!(parse_version("v1.2.3.4").is_none());
        assert!(parse_version("latest").is_none());
        assert!(parse_version("0.9.0") < parse_version("0.10.0"));
    }

    #[test]
    fn checksum_verification() {
        let data = b"hello";
        let h = hex(&Sha256::digest(data));
        assert!(verify_sha256(data, &format!("{h}  ndo4git-x\n"), "ndo4git-x").is_ok());
        assert!(verify_sha256(data, &h, "ndo4git-x").is_ok());
        assert!(verify_sha256(
            data,
            &format!("{}  ndo4git-x", h.to_uppercase()),
            "ndo4git-x"
        )
        .is_ok());
        assert!(verify_sha256(b"other", &format!("{h}  ndo4git-x"), "ndo4git-x").is_err());
        assert!(verify_sha256(data, &format!("{h}  something-else"), "ndo4git-x").is_err());
        assert!(verify_sha256(data, "", "ndo4git-x").is_err());
    }

    #[test]
    fn asset_selection() {
        let r: ApiRelease = serde_json::from_str(
            r#"{"tag_name":"v1.0.0","assets":[
                {"name":"ndo4git-x86_64-linux-musl","browser_download_url":"https://h/a"},
                {"name":"ndo4git-x86_64-linux-musl.sha256","browser_download_url":"https://h/a.sha256"}]}"#,
        )
        .unwrap();
        assert_eq!(
            select(&r, "x86_64").unwrap(),
            ("https://h/a", Some("https://h/a.sha256"))
        );
        assert!(select(&r, "aarch64").is_err());
    }
}
