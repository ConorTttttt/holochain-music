#!/usr/bin/env bash
# Build the Holo Web Conductor (HWC) Chromium extension used by the Music web client.
#
#   web/hwc/build-extension.sh HWC_CHECKOUT IMPOSTER_CHECKOUT
#
# HWC_CHECKOUT      clean clone of Holo-Host/holo-web-conductor at the pinned commit
# IMPOSTER_CHECKOUT ConorTttttt/imposter-holochain at the pinned browser baseline
#
# Applies, in order: Imposter's reviewed browser-alpha compatibility patches
# (cap-grant genesis/init, private entries, host-bound seeds, fail-closed
# remote signals, restricted gateway receiver), then the Music patches:
#   apply_multi_cell_routing.py     page zome calls reach the requested role
#   record-verification/apply.py    gateway records/links/details are verified
# The full HWC core test suite (including Imposter's *.imposter.test.ts and
# the malicious-gateway tests) must pass before the extension is built.
# Output: $HWC_CHECKOUT/packages/extension/dist-chrome
set -euo pipefail
fail() { echo "HWC build: $*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'usage: build-extension.sh HWC_CHECKOUT IMPOSTER_CHECKOUT'
here=$(cd "$(dirname "$0")" && pwd)
pins="$here/pins.json"
hwc=$(cd "$1" && pwd)
imposter=$(cd "$2" && pwd)
for tool in git jq node npm npx python3; do command -v "$tool" >/dev/null || fail "missing $tool"; done
test "$(git -C "$hwc" rev-parse HEAD)" = "$(jq -er .hwc_commit "$pins")" || fail 'HWC checkout is not at the pinned commit'
test "$(git -C "$imposter" rev-parse HEAD)" = "$(jq -er .imposter_baseline_commit "$pins")" || fail 'Imposter checkout is not at the pinned baseline'
test -z "$(git -C "$hwc" status --porcelain)" || fail 'use a clean HWC checkout'
kit="$imposter/compatibility/hwc-imposter-compatibility"
python3 "$kit/verify_pinned_sources.py" "$hwc"
# Imposter's apply.py refuses to write on any other branch name.
git -C "$hwc" switch -q -c fix/imposter-hwc-compatibility
python3 "$kit/apply.py" "$hwc" --write
python3 "$kit/private-role/apply_restricted_hwc_handler.py" "$hwc" --write
python3 "$kit/private-role/apply_installed_hwc_receiver.py" "$hwc" --write
python3 "$here/apply_multi_cell_routing.py" "$hwc"
python3 "$here/record-verification/apply.py" "$hwc"
git -C "$hwc" diff --check
(
  cd "$hwc"
  npm ci --no-audit --no-fund
  npx --no-install tsc -p packages/shared/tsconfig.json
  npx --no-install tsc -p packages/lair/tsconfig.json
  npx --no-install tsc -p packages/core/tsconfig.json
  npx --no-install tsc --noEmit -p packages/extension/tsconfig.json
  (cd packages/core && npx --no-install vitest run)
  npm run build:chrome --workspace @hwc/extension
)
echo "HWC extension: $hwc/packages/extension/dist-chrome"
