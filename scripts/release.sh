#!/bin/sh
# Build, sign and (optionally) publish a release.
#
#   scripts/release.sh              build + package + sign into dist/
#   scripts/release.sh --publish    also create the Codeberg release and upload
#                                   (needs CODEBERG_TOKEN, scope write:repository)
#
# Produces, for VERSION taken from Cargo.toml:
#   ndo4git-x86_64-linux-musl / ndo4git-aarch64-linux-musl   static, any Linux
#   ndo4git-x86_64-apple-darwin / ndo4git-aarch64-apple-darwin   macOS
#   ndo4git_VERSION_amd64.deb / ndo4git_VERSION_arm64.deb    Debian & Ubuntu
# each with a .sha256 and a detached .sig (ssh-keygen -Y sign, namespace
# ndo4git-release). `ndo4git update` refuses assets whose signature does not
# verify against the public key compiled into the binary.
#
# Needs: cargo-zigbuild + zig (cross targets; ZIG=/path/to/zig if not on PATH),
# dpkg-deb, ssh-keygen, and the release key (NDO4GIT_RELEASE_KEY, default
# ~/.config/ndo4git-release/release_ed25519).
set -eu
cd "$(dirname "$0")/.."

PUBLISH=0
[ "${1:-}" = "--publish" ] && PUBLISH=1

VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)
TAG="v$VERSION"
API="https://codeberg.org/api/v1/repos/NDO4ME/git"
KEY=${NDO4GIT_RELEASE_KEY:-$HOME/.config/ndo4git-release/release_ed25519}
NS=ndo4git-release

[ -f "$KEY" ] || { echo "release key $KEY not found" >&2; exit 1; }
# the key must be the one compiled into the binary, or `update` would reject every asset
EMBEDDED=$(sed -n 's/^const RELEASE_PUBKEY: &str = "\(ssh-ed25519 [^ ]*\) .*";$/\1/p' crates/ndo4git/src/update.rs)
[ "$EMBEDDED" = "$(cut -d' ' -f1,2 "$KEY.pub")" ] || { echo "$KEY does not match RELEASE_PUBKEY in update.rs" >&2; exit 1; }

[ -n "${ZIG:-}" ] && export CARGO_ZIGBUILD_ZIG_PATH=$ZIG
command -v cargo-zigbuild >/dev/null || { echo "cargo-zigbuild is required (cargo install cargo-zigbuild)" >&2; exit 1; }
command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required" >&2; exit 1; }

rm -rf dist && mkdir dist

build() { # rust-target asset-name
    rustup target add "$1" >/dev/null 2>&1 || true
    cargo zigbuild --release --locked --target "$1"
    cp "target/$1/release/ndo4git" "dist/$2"
    echo "built dist/$2"
}
build x86_64-unknown-linux-musl  ndo4git-x86_64-linux-musl
build aarch64-unknown-linux-musl ndo4git-aarch64-linux-musl
build x86_64-apple-darwin        ndo4git-x86_64-apple-darwin
build aarch64-apple-darwin       ndo4git-aarch64-apple-darwin

for a in x86_64 aarch64; do
    file "dist/ndo4git-$a-linux-musl" | grep -qE "statically linked|static-pie" \
        || { echo "ndo4git-$a-linux-musl is not static" >&2; exit 1; }
done
dist/ndo4git-x86_64-linux-musl --version | grep -q "$VERSION" \
    || { echo "binary reports the wrong version" >&2; exit 1; }

GEN_BIN=dist/ndo4git-x86_64-linux-musl scripts/build-deb.sh dist/ndo4git-x86_64-linux-musl  amd64 "dist/ndo4git_${VERSION}_amd64.deb"
GEN_BIN=dist/ndo4git-x86_64-linux-musl scripts/build-deb.sh dist/ndo4git-aarch64-linux-musl arm64 "dist/ndo4git_${VERSION}_arm64.deb"

ALLOWED=$(mktemp); trap 'rm -f "$ALLOWED" "${HDR:-}"' EXIT
echo "$NS $(cut -d' ' -f1,2 "$KEY.pub")" > "$ALLOWED"
for f in dist/*; do
    n=$(basename "$f")
    (cd dist && sha256sum "$n" > "$n.sha256")
    ssh-keygen -q -Y sign -f "$KEY" -n "$NS" "$f"          # writes "$f.sig"
    ssh-keygen -q -Y verify -f "$ALLOWED" -I "$NS" -n "$NS" -s "$f.sig" < "$f" >/dev/null \
        || { echo "signature self-check failed for $n" >&2; exit 1; }
done
echo "dist/ ready for $TAG:"; ls -l dist

[ "$PUBLISH" = 1 ] || { echo "(not published; use --publish)"; exit 0; }

: "${CODEBERG_TOKEN:?set CODEBERG_TOKEN (Codeberg > Settings > Applications, scope: write:repository)}"
git diff --quiet && git diff --cached --quiet || { echo "working tree not clean" >&2; exit 1; }
git fetch -q origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "push HEAD to origin/main first" >&2; exit 1; }

# keep the token out of `ps`: pass the header through a private file
HDR=$(mktemp); chmod 600 "$HDR"
printf 'Authorization: token %s\n' "$CODEBERG_TOKEN" > "$HDR"

echo "creating release $TAG"
BODY=$(printf '{"tag_name":"%s","target_commitish":"main","name":"%s","body":"ndo4git %s\\n\\nLinux (static, any distro): ndo4git-<arch>-linux-musl\\nmacOS: ndo4git-<arch>-apple-darwin\\nDebian/Ubuntu: ndo4git_%s_<amd64|arm64>.deb\\n\\nEvery asset has a .sha256 and a .sig (ssh-keygen -Y sign, namespace ndo4git-release)."}' "$TAG" "$TAG" "$VERSION" "$VERSION")
resp=$(curl -fsS -X POST "$API/releases" -H @"$HDR" -H "Content-Type: application/json" -d "$BODY")
id=$(printf '%s' "$resp" | sed -n 's/^{"id":\([0-9][0-9]*\).*/\1/p')
[ -n "$id" ] || { echo "unexpected reply: $resp" >&2; exit 1; }

for f in dist/*; do
    echo "uploading $(basename "$f")"
    curl -fsS -X POST "$API/releases/$id/assets?name=$(basename "$f")" \
        -H @"$HDR" -F "attachment=@$f" >/dev/null
done
echo "published $TAG: https://codeberg.org/NDO4ME/git/releases/tag/$TAG"
