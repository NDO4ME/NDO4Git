#!/bin/sh
# Build static release binaries into dist/ and optionally publish them as a
# Codeberg release, which is what `ndo4git update` downloads.
#
#   scripts/release.sh              build + checksums only
#   scripts/release.sh --publish    also tag + upload (needs CODEBERG_TOKEN)
#
# aarch64 is built when `cross` is installed (or WITH_AARCH64=1 and a musl
# cross compiler is configured); otherwise it is skipped with a warning.
set -eu
cd "$(dirname "$0")/.."

PUBLISH=0
[ "${1:-}" = "--publish" ] && PUBLISH=1

VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n1)
TAG="v$VERSION"
API="https://codeberg.org/api/v1/repos/NDO4ME/git"
rm -rf dist && mkdir dist

build() { # target arch
    target=$1 arch=$2
    rustup target add "$target" >/dev/null 2>&1 || true
    if [ "$arch" = x86_64 ]; then
        cargo build --release --locked --target "$target"
    elif command -v cross >/dev/null 2>&1; then
        cross build --release --locked --target "$target"
    elif [ "${WITH_AARCH64:-0}" = 1 ]; then
        cargo build --release --locked --target "$target"
    else
        echo "warning: skipping $arch (install 'cross' or set WITH_AARCH64=1 with a musl cross compiler)" >&2
        return 0
    fi
    name="ndo4git-$arch-linux-musl"
    cp "target/$target/release/ndo4git" "dist/$name"
    (cd dist && sha256sum "$name" > "$name.sha256")
    echo "built dist/$name"
}

build x86_64-unknown-linux-musl x86_64
build aarch64-unknown-linux-musl aarch64

for f in dist/ndo4git-x86_64-linux-musl; do
    file "$f" | grep -qE "statically linked|static-pie" || { echo "$f is not static" >&2; exit 1; }
    "$f" --version | grep -q "$VERSION" || { echo "$f reports the wrong version" >&2; exit 1; }
done

[ "$PUBLISH" = 1 ] || { echo "dist/ ready for $TAG (not published; use --publish)"; exit 0; }

: "${CODEBERG_TOKEN:?set CODEBERG_TOKEN (Codeberg > Settings > Applications, scope: write:repository)}"
git diff --quiet && git diff --cached --quiet || { echo "working tree not clean" >&2; exit 1; }
git fetch -q origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo "push HEAD to origin/main first" >&2; exit 1; }

echo "creating release $TAG"
resp=$(curl -fsS -X POST "$API/releases" \
    -H "Authorization: token $CODEBERG_TOKEN" -H "Content-Type: application/json" \
    -d "{\"tag_name\":\"$TAG\",\"target_commitish\":\"main\",\"name\":\"$TAG\",\"body\":\"ndo4git $VERSION\"}")
id=$(printf '%s' "$resp" | sed -n 's/^{"id":\([0-9][0-9]*\).*/\1/p')
[ -n "$id" ] || { echo "unexpected reply: $resp" >&2; exit 1; }

for f in dist/*; do
    echo "uploading $(basename "$f")"
    curl -fsS -X POST "$API/releases/$id/assets?name=$(basename "$f")" \
        -H "Authorization: token $CODEBERG_TOKEN" -F "attachment=@$f" >/dev/null
done
echo "published $TAG: https://codeberg.org/NDO4ME/git/releases/tag/$TAG"
