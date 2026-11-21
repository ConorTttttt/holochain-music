#!/usr/bin/env bash
# Build the H2HC gateway CANDIDATE with standard Holochain call_remote.
#
#   web/gateway/build-candidate.sh H2HC_CHECKOUT IMPOSTER_CHECKOUT OUT_DIR
#
# H2HC_CHECKOUT     clean clone of Holo-Host/h2hc-linker (any branch; must contain the pin)
# IMPOSTER_CHECKOUT ConorTttttt/imposter-holochain with commit 293563649f... available
# OUT_DIR           new directory for the binary, SHA256SUMS and provenance
#
# 1. Reproduces the ACCEPTED gateway source exactly as Imposter's recorded
#    recipe (.github/workflows/agent3-h2hc-security.yml at recipe_commit):
#    upstream pin cab242d3 + three security patches + compiler fixes +
#    regression fixes + revocation + cargo fmt + restricted role relay.
# 2. Applies web/gateway/call-remote.patch (this repository) on top.
# 3. cargo fmt --check, cargo test --locked, cargo clippy -D warnings.
# 4. Builds the debug binary like the accepted build (stripped of debug info).
# The accepted binary (sha256 in web/hwc/pins.json) is never modified.
set -euo pipefail
fail() { echo "gateway candidate: $*" >&2; exit 1; }
[[ $# == 3 ]] || fail 'usage: build-candidate.sh H2HC_CHECKOUT IMPOSTER_CHECKOUT OUT_DIR'
here=$(cd "$(dirname "$0")" && pwd)
pins="$here/../hwc/pins.json"
h2hc=$(cd "$1" && pwd)
imposter=$(cd "$2" && pwd)
out=$(realpath -m "$3")
[[ ! -e "$out" ]] || fail 'OUT_DIR must not exist'
pin=cab242d32c988fe5e4e9fd06ebc82ed043541aa2
recipe=$(jq -er .gateway.recipe_commit "$pins")
test -z "$(git -C "$h2hc" status --porcelain)" || fail 'use a clean h2hc checkout'
git -C "$imposter" cat-file -e "$recipe^{commit}" || fail "Imposter recipe $recipe not fetched"

kit=$(mktemp -d)
trap 'rm -rf "$kit"' EXIT
for p in part00 part01 part02; do git -C "$imposter" show "$recipe:ci/agent3-h2hc-kit/$p.b64"; done | base64 --decode > "$kit/kit.tar.xz"
echo "afcf5c406b6b6040ac00060d31052a9eaa121c5b8540ca6a7354898b6752be62  $kit/kit.tar.xz" | sha256sum --check --quiet
tar -xJf "$kit/kit.tar.xz" -C "$kit"
mkdir "$kit/ci"
for f in apply_rust_regression_fixes.py apply_revocation_patch.py apply_private_role_relay.py private_role.rs; do
  git -C "$imposter" show "$recipe:ci/agent3-h2hc-kit/$f" > "$kit/ci/$f"
done

cd "$h2hc"
git checkout -q --detach "$pin"
export GIT_AUTHOR_NAME=gateway-candidate GIT_AUTHOR_EMAIL=gateway-candidate@localhost
export GIT_COMMITTER_NAME=gateway-candidate GIT_COMMITTER_EMAIL=gateway-candidate@localhost
bash "$kit/agent3-h2hc-patches/run_security_checks.sh" --apply-only
python3 - "$h2hc" <<'PY'
import subprocess, sys
from pathlib import Path
root = Path(sys.argv[1])
g = root / "src/gateway_kitsune.rs"; c = g.read_text()
old = "let signal_data = signal_to_b64(&ExternIO(signal.zome_call_params.clone()));"
assert c.count(old) == 1 and "use base64::Engine;" not in c
c = c.replace(old, "let signal_data = base64::engine::general_purpose::STANDARD.encode(&signal.zome_call_params);", 1)
g.write_text(c.replace("use bytes::Bytes;", "use base64::Engine;\nuse bytes::Bytes;", 1))
w = root / "src/routes/websocket.rs"; c = w.read_text()
assert c.count("state.registrations.push(key);") == 1
w.write_text(c.replace("state.registrations.push(key);", "state.registrations.push(key.clone());", 1))
subprocess.run(["git", "-C", str(root), "commit", "-qam", "security: fix signal encoder and registration key ownership"], check=True)
PY
python3 "$kit/ci/apply_rust_regression_fixes.py" --repo .
git commit -qam "security: correct Rust regression fixtures and targeted Clippy errors"
python3 "$kit/ci/apply_revocation_patch.py" --repo .
git commit -qam "security: revoke every active websocket and close session race"
cargo fmt
git diff --quiet || git commit -qam "style: cargo fmt"
python3 "$kit/ci/apply_private_role_relay.py" --repo .
cargo fmt
git add src && git commit -qm "security: bounded opaque role-request and role-delivery relay"
accepted_tree=$(git rev-parse HEAD^{tree})
echo "Reproduced accepted gateway source tree: $accepted_tree"

git apply --check "$here/call-remote.patch"
git apply "$here/call-remote.patch"
git add -A src && git commit -qm "call_remote: authenticated standard Holochain call_remote relay (candidate)"
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --bin h2hc-linker
mkdir -p "$out"
target_dir=$(cargo metadata --format-version 1 --no-deps | jq -r .target_directory)
cp "$target_dir/debug/h2hc-linker" "$out/h2hc-linker-call-remote-candidate"
strip --strip-debug "$out/h2hc-linker-call-remote-candidate"
(cd "$out" && sha256sum h2hc-linker-call-remote-candidate > SHA256SUMS)
{
  echo "H2HC_UPSTREAM=$pin"
  echo "IMPOSTER_RECIPE=$recipe"
  echo "ACCEPTED_SOURCE_TREE=$accepted_tree"
  echo "CANDIDATE_SOURCE_TREE=$(git rev-parse HEAD^{tree})"
  echo "CALL_REMOTE_PATCH_SHA256=$(sha256sum "$here/call-remote.patch" | cut -d' ' -f1)"
  echo "RUSTC=$(rustc --version)"
} > "$out/build-provenance.txt"
cat "$out/SHA256SUMS" "$out/build-provenance.txt"
