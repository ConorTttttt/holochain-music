#!/bin/sh
# Private, exact-commit release-candidate builder; creates NO release or tag.
# Usage: packaging/rc-build.sh linux|windows FULL_40_CHAR_COMMIT [OUTDIR]
# Always builds Linux Rust/DNA sources afresh; --skip-build is intentionally
# not supported here. Windows native helpers must be CI-built from this commit.
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || { echo "usage: $0 linux|windows FULL_COMMIT [OUTDIR]" >&2; exit 2; }
target=$1
commit=$2
out=${3:-"$repo/dist"}
python3 "$repo/packaging/rc-evidence.py" preflight --commit "$commit"
SOURCE_DATE_EPOCH=$(git -C "$repo" show -s --format=%ct "$commit")
export SOURCE_DATE_EPOCH
mkdir -p "$out"
out=$(cd "$out" && pwd)
# Do not overwrite an older package (even if it uses the same version label).
version=$(cd "$repo" && python3 -c 'from holochain_music import __version__; print(__version__)')
case "$target" in
  linux)
    debversion=$(printf '%s' "$version" | sed 's/rc/~rc/')
    artifact="$out/holochain-music_${debversion}_amd64.deb"
    contents="$out/holochain-music_${debversion}_contents.sha256"
    for var in HOLOCHAIN_BIN HC_BIN KITSUNE2_BOOTSTRAP_SRV_BIN HM_RC_LINUX_INPUTS_SHA256; do
      eval "value=\${$var:-}"
      [ -n "$value" ] || { echo "error: $var must be set (use reviewed, SHA-pinned Linux binaries)" >&2; exit 3; }
    done
    # This manifest must originate from reviewed third-party inputs; its hash
    # and the binaries themselves are retained in external provenance.
    sha256sum --check "$HM_RC_LINUX_INPUTS_SHA256"
    # The approved manifest must cover the actual three selected binaries.
    for binary in "$HOLOCHAIN_BIN" "$HC_BIN" "$KITSUNE2_BOOTSTRAP_SRV_BIN"; do
      line=$(sha256sum -- "$binary")
      grep -Fqx -- "$line" "$HM_RC_LINUX_INPUTS_SHA256" || {
        echo "error: selected input $binary absent/mismatched in approved manifest" >&2
        exit 4
      }
    done
    [ ! -e "$artifact" ] && [ ! -e "$contents" ] &&
    [ ! -e "$artifact.sha256" ] && [ ! -e "$artifact.provenance.json" ] || {
      echo "error: candidate or evidence sidecar already exists" >&2; exit 5;
    }
    "$repo/packaging/build-deb.sh" "$out"
    python3 "$repo/packaging/rc-evidence.py" record --commit "$commit" --platform linux \
      --artifact "$artifact" --contents "$contents" \
      --input "holochain=$HOLOCHAIN_BIN" --input "hc=$HC_BIN" \
      --input "bootstrap=$KITSUNE2_BOOTSTRAP_SRV_BIN" \
      --input "approved-linux-input-manifest=$HM_RC_LINUX_INPUTS_SHA256"
    ;;
  windows)
    winversion=$(printf '%s' "$version" | sed 's/rc/-rc/')
    artifact="$out/HolochainMusic-${winversion}-windows-x64.exe"
    contents="$out/HolochainMusic-${winversion}-windows-x64.contents.sha256"
    for var in HM_WIN_UPSTREAM HM_WIN_PYTHON HM_WIN_WHEELS HM_WIN_MOQ HM_WIN_BRIDGE; do
      eval "value=\${$var:-}"
      [ -n "$value" ] || { echo "error: $var must be set" >&2; exit 3; }
    done
    [ -z "${HM_WIN_LAUNCHERS:-}" ] || { echo "error: RC must rebuild launchers, not import untracked prebuilt launchers" >&2; exit 3; }
    [ ! -e "$artifact" ] && [ ! -e "$contents" ] &&
    [ ! -e "$artifact.sha256" ] && [ ! -e "$artifact.provenance.json" ] || {
      echo "error: candidate or evidence sidecar already exists" >&2; exit 5;
    }
    "$repo/packaging/windows/build-windows.sh" "$out"
    python3 "$repo/packaging/rc-evidence.py" record --commit "$commit" --platform windows \
      --artifact "$artifact" --contents "$contents" \
      --input "third-party-pin-manifest=$repo/packaging/windows/inputs.sha256" \
      --input "moq-native-helper=$HM_WIN_MOQ" --input "bridge-native-helper=$HM_WIN_BRIDGE" \
      --input "python-runtime=$HM_WIN_PYTHON"
    ;;
  *) echo "error: choose linux or windows" >&2; exit 2 ;;
esac
echo "DRAFT private RC evidence created in $out; no publication or approval."
