#!/bin/sh
# Assemble the Windows x64 test installer on Linux (or any POSIX host).
#
#   packaging/windows/build-windows.sh [OUTDIR]
#
# Required environment (all inputs except our own two Rust binaries are
# verified against packaging/windows/inputs.sha256 and refused on mismatch):
#   HM_WIN_UPSTREAM  dir with holochain-, hc- and kitsune2-bootstrap-srv-
#                    x86_64-pc-windows-msvc.exe (Holochain 0.7.0 release)
#   HM_WIN_PYTHON    path to python-3.14.10-embed-amd64.zip
#   HM_WIN_WHEELS    dir with the four pinned win_amd64 wheels
#   HM_WIN_MOQ       holochain-music-moq.exe   (crates/moq-music, Windows target)
#   HM_WIN_BRIDGE    music_app_bridge.exe      (music-e2e, Windows target)
# Optional:
#   MAKENSIS (default: makensis on PATH; NSISDIR is honoured)
#   CC_WIN (default x86_64-w64-mingw32-gcc), WINDRES (default x86_64-w64-mingw32-windres)
#   HM_WIN_LAUNCHERS dir with prebuilt HolochainMusic.exe + holochain-music.exe
#
# Output: OUTDIR/HolochainMusic-<version>-windows-x64.exe and
#         OUTDIR/HolochainMusic-<version>-windows-x64.contents.sha256
set -eu
umask 022
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
out=${1:-$repo/dist}
pyver=$(python3 -c "import re;print(re.search(r'__version__ = \"(.+)\"', open('$repo/holochain_music/__init__.py').read()).group(1))")
version=$(echo "$pyver" | sed 's/rc/-rc/')          # 1.0.0rc1 -> 1.0.0-rc1
artefact="HolochainMusic-$(echo "$version" | sed 's/-rc[0-9]*$/-rc/')-windows-x64.exe"   # name agreed for private testing
# Reproducibility: PE timestamps (ld/strip) and NSIS file times follow this.
: "${SOURCE_DATE_EPOCH:=$(git -C "$repo" log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH

need() { eval "v=\${$1:-}"; [ -n "$v" ] || { echo "error: set $1" >&2; exit 2; }; }
for v in HM_WIN_UPSTREAM HM_WIN_PYTHON HM_WIN_WHEELS HM_WIN_MOQ HM_WIN_BRIDGE; do need $v; done

pinned() {  # pinned FILE -> exits unless FILE's sha256 is listed for its basename
  name=$(basename "$1")
  want=$(awk -v n="$name" '$2==n {print $1}' "$here/inputs.sha256")
  [ -n "$want" ] || { echo "error: $name is not a pinned input" >&2; exit 3; }
  got=$(sha256sum "$1" | cut -d' ' -f1)
  [ "$got" = "$want" ] || { echo "error: $name sha256 $got != pinned $want" >&2; exit 3; }
  echo "verified $name"
}

stage=$(mktemp -d "${TMPDIR:-/tmp}/hm-win.XXXXXX")
trap 'rm -rf "$stage"' EXIT
root=$stage/HolochainMusic
mkdir -p "$root/bin" "$root/python" "$root/runtime" "$root/docs" "$root/licenses"

# --- native helpers ---------------------------------------------------------
for tool in holochain hc kitsune2-bootstrap-srv; do
  src="$HM_WIN_UPSTREAM/$tool-x86_64-pc-windows-msvc.exe"
  pinned "$src"
  install -m 0755 "$src" "$root/bin/$tool.exe"
done
install -m 0755 "$HM_WIN_MOQ" "$root/bin/holochain-music-moq.exe"
install -m 0755 "$HM_WIN_BRIDGE" "$root/bin/music_app_bridge.exe"
x86_64-w64-mingw32-strip --strip-unneeded "$root/bin/holochain-music-moq.exe" "$root/bin/music_app_bridge.exe" 2>/dev/null || true

# --- Python runtime ---------------------------------------------------------
pinned "$HM_WIN_PYTHON"
(cd "$root/runtime" && unzip -q "$HM_WIN_PYTHON")
pth=$(cd "$root/runtime" && ls python3*._pth)
zipname=$(cd "$root/runtime" && ls python3*.zip)
# Isolated search path: stdlib zip, runtime dir, bundled wheels, app packages.
printf '%s\r\n.\r\nLib\\site-packages\r\n..\\python\r\n' "$zipname" > "$root/runtime/$pth"
# The upstream MSVC binaries import VCRUNTIME140.dll; ship the same app-local
# copy python.org ships, beside them (Visual C++ redistributable terms).
cp "$root/runtime/vcruntime140.dll" "$root/bin/vcruntime140.dll"
site=$root/runtime/Lib/site-packages
mkdir -p "$site"
for whl in cryptography-47.0.0-cp311-abi3-win_amd64.whl cffi-2.1.1-cp314-cp314-win_amd64.whl \
           pycparser-3.12-py3-none-any.whl sounddevice-0.5.6-py3-none-win_amd64.whl; do
  pinned "$HM_WIN_WHEELS/$whl"
  (cd "$site" && unzip -q -o "$HM_WIN_WHEELS/$whl")
done
# PortAudio: keep only the x64 build without ASIO (WASAPI/MME/DirectSound/WDM-KS).
pa=$site/_sounddevice_data/portaudio-binaries
find "$pa" -mindepth 1 ! -name libportaudio64bit.dll ! -name README.md -exec rm -rf {} +
[ -f "$pa/libportaudio64bit.dll" ] || { echo "error: PortAudio DLL missing" >&2; exit 4; }

# --- application ------------------------------------------------------------
for pkg in holochain_music music_catalogue holochain_storage; do
  (cd "$repo" && find "$pkg" -type f \( -name '*.py' -o -path '*/ui/*' \) ! -path '*__pycache__*' | sort) |
    while read -r f; do install -D -m 0644 "$repo/$f" "$root/python/$f"; done
done
install -m 0644 "$repo/integration/workdir/holochain_music.happ" "$root/holochain_music.happ"

# --- launchers and icon -----------------------------------------------------
python3 "$here/make_icon.py" "$root/HolochainMusic.ico"
if [ -n "${HM_WIN_LAUNCHERS:-}" ]; then
  install -m 0755 "$HM_WIN_LAUNCHERS/HolochainMusic.exe" "$HM_WIN_LAUNCHERS/holochain-music.exe" "$root/"
else
  cc=${CC_WIN:-x86_64-w64-mingw32-gcc}
  windres=${WINDRES:-x86_64-w64-mingw32-windres}
  cp "$root/HolochainMusic.ico" "$stage/holochain-music.ico"
  (cd "$stage" && "$windres" "$here/launcher.rc" --include-dir "$stage" -O coff -o launcher.res)
  "$cc" -O2 -municode -mwindows -DHM_GUI -static -s -Wall -o "$root/HolochainMusic.exe" "$here/launcher.c" "$stage/launcher.res"
  "$cc" -O2 -municode -static -s -Wall -o "$root/holochain-music.exe" "$here/launcher.c" "$stage/launcher.res"
fi

# --- documents and licences -------------------------------------------------
install -m 0644 "$here/PRIVATE-TEST-NOTICE.txt" "$root/PRIVATE-TEST-NOTICE.txt"
for doc in README.md CHANGELOG.md docs/windows-installation.md docs/windows-lan-test-plan.md \
           docs/security-model.md docs/licensing-audit.md docs/user-guide.md; do
  [ -f "$repo/$doc" ] && install -m 0644 "$repo/$doc" "$root/docs/$(basename "$doc")"
done
[ -f "$root/docs/windows-installation.md" ] && cp "$root/docs/windows-installation.md" "$root/docs/windows-installation.txt"
install -m 0644 "$here/licenses/"*.txt "$here/THIRD-PARTY.txt" "$root/licenses/"
cp "$root/runtime/LICENSE.txt" "$root/licenses/Python-LICENSE.txt"

# --- manifest and installer ------------------------------------------------
find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
(cd "$root" && find . -type f ! -name SHA256SUMS.txt | sed 's#^\./##' | LC_ALL=C sort | while read -r f; do sha256sum "$f"; done) > "$stage/SHA256SUMS.txt"
cp "$stage/SHA256SUMS.txt" "$root/SHA256SUMS.txt"
touch -h -d "@$SOURCE_DATE_EPOCH" "$root/SHA256SUMS.txt"
size_kb=$(find "$root" -type f -printf '%s\n' | awk '{s+=$1} END {print int((s+1023)/1024)}')
mkdir -p "$out"
${MAKENSIS:-makensis} -V2 -DVERSION="$version" -DSTAGE="$root" -DSIZE_KB="$size_kb" \
  -DOUTFILE="$out/$artefact" "$here/installer.nsi"
cp "$stage/SHA256SUMS.txt" "$out/${artefact%.exe}.contents.sha256"
sha256sum "$out/$artefact"
