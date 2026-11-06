#!/bin/sh
# Reproducible .deb assembly for Holochain Music.
#
#   packaging/build-deb.sh [--skip-build] [OUTDIR]
#
# Builds (unless --skip-build) the zomes, DNAs, hApp, MoQ host and app bridge
# from the locked sources, then assembles a .deb with a fixed file order,
# fixed mtimes (SOURCE_DATE_EPOCH) and root ownership, and prints SHA-256s.
# Inputs: holochain, hc and kitsune2-bootstrap-srv 0.7.x on PATH (or *_BIN).
set -eu
umask 022
repo=$(cd "$(dirname "$0")/.." && pwd)
skip=0
if [ "${1:-}" = "--skip-build" ]; then skip=1; shift; fi
out=${1:-$repo/dist}
version=$(python3 -c "import re;print(re.search(r'__version__ = \"(.+)\"', open('$repo/holochain_music/__init__.py').read()).group(1).replace('rc','~rc'))")
: "${SOURCE_DATE_EPOCH:=$(git -C "$repo" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
bridge=${HOLOCHAIN_MUSIC_BRIDGE_BIN:-$repo/music-e2e/target/release/music_app_bridge}
moq=${HOLOCHAIN_MOQ_BIN:-$repo/crates/moq-music/target/release/holochain-music-moq}

if [ $skip -eq 0 ]; then
  (cd "$repo/music-dna" && cargo build --locked --release --target wasm32-unknown-unknown && hc dna pack workdir)
  (cd "$repo/dna" && cargo build --locked --release --target wasm32-unknown-unknown && hc dna pack workdir)
  cp "$repo/music-dna/workdir/music_catalogue.dna" "$repo/dna/workdir/music_storage.dna" "$repo/integration/workdir/"
  hc app pack "$repo/integration/workdir"
  (cd "$repo/crates/moq-music" && cargo build --locked --release)
  (cd "$repo/music-e2e" && cargo build --locked --release --bin music_app_bridge)
fi

stage=$(mktemp -d "${TMPDIR:-/tmp}/hm-deb.XXXXXX")
trap 'rm -rf "$stage"' EXIT
root=$stage/root
lib=$root/usr/lib/holochain-music
mkdir -p "$lib/bin" "$lib/python" "$root/usr/bin" "$root/usr/share/applications" \
         "$root/usr/share/icons/hicolor/scalable/apps" "$root/usr/share/doc/holochain-music" "$root/DEBIAN"
for tool in holochain hc kitsune2-bootstrap-srv; do
  var=$(echo "$tool" | tr 'a-z-' 'A-Z_')_BIN
  src=$(eval echo "\${$var:-}"); [ -n "$src" ] || src=$(command -v "$tool")
  install -m 0755 "$src" "$lib/bin/$tool"
done
install -m 0755 "$moq" "$lib/bin/holochain-music-moq"
install -m 0755 "$bridge" "$lib/bin/music_app_bridge"
strip --strip-unneeded "$lib/bin/"* 2>/dev/null || true
install -m 0644 "$repo/integration/workdir/holochain_music.happ" "$lib/holochain_music.happ"
for pkg in holochain_music music_catalogue holochain_storage; do
  (cd "$repo" && find "$pkg" -type f \( -name '*.py' -o -path '*/ui/*' \) ! -path '*__pycache__*' | sort) |
    while read -r f; do install -D -m 0644 "$repo/$f" "$lib/python/$f"; done
done
install -m 0755 "$repo/packaging/holochain-music.sh" "$root/usr/bin/holochain-music"
install -m 0644 "$repo/packaging/holochain-music.desktop" "$root/usr/share/applications/holochain-music.desktop"
install -m 0644 "$repo/holochain_music/ui/icon.svg" "$root/usr/share/icons/hicolor/scalable/apps/holochain-music.svg"
for doc in README.md CHANGELOG.md docs/v1-release-readiness.md docs/security-model.md docs/user-guide.md docs/installation.md packaging/smoke-test.py; do
  if [ -f "$repo/$doc" ]; then install -m 0644 "$repo/$doc" "$root/usr/share/doc/holochain-music/$(basename "$doc")"; fi
done
(cd "$root" && find usr -type f | sort | xargs sha256sum) > "$root/DEBIAN/md5sums.sha256"
mv "$root/DEBIAN/md5sums.sha256" "$stage/SHA256SUMS"
# Byte-based (not du) so the control file does not depend on filesystem blocks.
size=$(find "$root/usr" -type f -printf '%s\n' | awk '{s+=$1} END {print int((s+1023)/1024)}')
sed -e "s/@VERSION@/$version/" -e "s/@SIZE@/$size/" "$repo/packaging/debian/control.in" > "$root/DEBIAN/control"
find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
mkdir -p "$out"
deb="$out/holochain-music_${version}_amd64.deb"
fakeroot dpkg-deb --root-owner-group -Zxz --build "$root" "$deb" >/dev/null
cp "$stage/SHA256SUMS" "$out/holochain-music_${version}_contents.sha256"
sha256sum "$deb"
