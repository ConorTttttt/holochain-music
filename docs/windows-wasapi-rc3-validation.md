# Private Windows rc3 validation — 2026-11-06

Local `feat/v1-windows-port`, base `877664c766b1445743769fb6376c43c60b51286b`
plus the existing uncommitted rc2 implementation and this rc3 patch. Nothing
pushed, merged, tagged or published. Physical Windows speaker retest PENDING.

## Executed checks

| Check | Result |
|---|---|
| Final complete Python suite, real local MoQ/QUIC and storage | PASS: 359 tests run, 130.389 s, 13 skipped |
| Audio lifecycle/quality coverage | 28 lifecycle + 9 quality/metadata tests; all included above |
| Added since rc2 | 11 tests: 9 quality/metadata and two 20-operation lifecycle stress cases |
| Native MoQ Rust suite | PASS: 8 tests plus doctests |
| Native storage DNA Rust suite | PASS: 3 tests plus coordinator/doctest targets |
| Native catalogue DNA Rust suite | PASS: 6 tests plus coordinator/doctest targets |
| Native storage node Rust suite | PASS: builds/runs its test target (0 tests defined) |
| Windows MoQ release, locked/offline | PASS: x86_64-pc-windows-gnu |
| Windows MoQ tests, locked/offline --no-run | PASS: test executables compiled, NOT executed on Linux |
| Windows bridge release, locked/offline | PASS: established portable static libsodium input |
| Native WASAPI smoke script | SKIP: Windows host required; extended to real 44.1/48 kHz output and interruption checks |
| Python, UI JavaScript and shell syntax; git diff whitespace | PASS |

The 13 skips are seven opt-in conductor/grant-security tests, four Windows-only
tests and two built-installer tests. The latter are enabled separately after
packaging. No conductor integration rerun is implied by the native DNA unit
tests. No Windows runtime or speaker pass is implied by cross-builds.

## Before/after measurements

Raw JSON, test/build logs and saved rc2 pipeline modules: `dist/rc3-validation/`.
`windows-wasapi-rc3.md` explains the controlled scheduling model and format audit.

- Identical 12-second PCM model, 2 ms added per SOFTWARE pacing wait:
  rc2 228 underruns, 12.902 s, callback max 0.069 ms, occupancy 0–35,280 B;
  rc3 0 underruns, 12.002 s, callback max 0.101 ms, occupancy 0–70,560 B.
  Both delivered all 2,116,800 source bytes with the exact expected digest.
  This reproduces inserted-silence starvation, not physical Windows crackling.
- Separate 180-second real-time rc3 model: 0 underruns, 31,752,000 exact bytes,
  18,002 callbacks; callback max 0.089 ms, interval max 18.662 ms. One stream
  start, zero starvation/rebuffer silence. The model cannot measure actual
  native underflow flags. Startup/EOF account for occupancy minimum zero.
- Authenticated offline three-minute stereo test: exact captured/delivered
  digest through signed manifest, licence, SHA-256 and AES-GCM gates, including
  arbitrary callbacks and ring wraps. Accelerated manual device time.
- ALSA null-device benchmark, licensed 5:31 stereo WAV, 20 seeks:
  rc2 median 2.4 ms / p95 2.6 ms; rc3 median 2.4 ms / p95 2.8 ms.
  Both zero timeouts, backwards positions or static-position stalls.
- Instrumented WASAPI device, 20 alternating seeks + pause/resume/stop/reopen:
  rc2 first-write median 1.1 ms / max 10.5 ms; rc3 median 1.0 ms / max 1.9 ms
  in the final full suite (standalone max 1.5 ms). The same 20-switch test passes
  on saved rc2 and rc3. These are first-write/controller metrics, not sound.
- Existing 15-seek null regression: final median 0.9 ms / p95 1.2 ms.

Callback duration maxima depend on concurrent host load and are not claimed
as a speedup. The evidence supports fixing producer-rate starvation while
preserving teardown/seek behavior. Hardware causality remains unconfirmed.

## Reproduce

```sh
python3 packaging/bench-wasapi-buffer.py --seconds 12 --pacer-delay-ms 2 \
  --baseline-audio dist/rc3-validation/rc2-audio-output.py \
  --baseline-buffered dist/rc3-validation/rc2-buffered.py --json /tmp/before.json
python3 packaging/bench-wasapi-buffer.py --seconds 12 --pacer-delay-ms 2 --json /tmp/after.json
python3 packaging/bench-wasapi-buffer.py --seconds 180 --json /tmp/soak.json

HOLOCHAIN_MOQ_BIN=<current Linux MoQ binary with serve subcommand> \
HOLOCHAIN_STORAGE_NODE_BIN=<Linux storage-node binary> \
  python3 -m unittest discover -s tests -v
python3 packaging/bench-seek.py --seconds 331 --seeks 20 --interval 0.2 \
  --device null --json /tmp/alsa.json

cargo test --locked --offline --manifest-path crates/moq-music/Cargo.toml
cargo test --offline --manifest-path crates/storage-node/Cargo.toml
cargo test --locked --offline --manifest-path dna/Cargo.toml
cargo test --locked --offline --manifest-path music-dna/Cargo.toml
cargo build --locked --offline --release --target x86_64-pc-windows-gnu \
  --manifest-path crates/moq-music/Cargo.toml
cargo test --locked --offline --target x86_64-pc-windows-gnu --no-run \
  --manifest-path crates/moq-music/Cargo.toml
(cd music-e2e && SODIUM_LIB_DIR=/mnt/holochain/tmp/hm-sodium-mingw/install/lib \
  CARGO_TARGET_DIR=target-win cargo build --locked --offline --release \
  --target x86_64-pc-windows-gnu --bin music_app_bridge)
```

Native tests used isolated `CARGO_TARGET_DIR`, `CARGO_PROFILE_DEV_DEBUG=0`
and `CARGO_BUILD_JOBS=2`. Initial native builds exhausted workspace space,
then /tmp quota; only this turn's generated build caches were removed/moved.
The successful run used reduced-debug outputs and cached dependencies.
An initial Python run used an outdated Linux MoQ helper lacking `serve`;
it was rebuilt from this branch before the passing complete suite. A new test
initially used a stereo-sized buffer for a mono fixture; it was corrected to
use the actual frame size, and the complete final suite passed afterwards.

## Files changed for rc3

Relative to the pre-existing rc2 worktree (which already contained uncommitted
lifecycle, CLI/app and packaging work):

- `music_catalogue/audio_output.py`: fixed ring, device backpressure interface,
  prebuffer/recovery, callback-safe PCM copies, health/format/native telemetry.
- `music_catalogue/buffered_playback.py`: WASAPI pacing, pause propagation,
  callback-consumed progress and diagnostics.
- `holochain_music/player.py`, `holochain_music/ui/app.js`: volume-wrapper
  forwarding, WASAPI ring configuration and visible interruption badge.
- `tests/test_wasapi_quality.py` (new), `tests/test_wasapi_lifecycle.py`,
  `tests/test_windows_port.py`: quality/stress regressions and bounded fake clock.
- `packaging/bench-wasapi-buffer.py` (new), `packaging/windows/smoke-wasapi.py`:
  reproducible model and extended native smoke.
- `holochain_music/__init__.py`, `pyproject.toml`, `CHANGELOG.md`,
  `packaging/windows/PRIVATE-TEST-NOTICE.txt`,
  `packaging/windows/build-windows.sh`: rc3 identity and bundled report.
- `docs/windows-wasapi-rc3.md` and this validation report (new),
  `docs/windows-installation.md`, `docs/windows-lan-test-plan.md`,
  `docs/v1-release-readiness.md`, `docs/windows-rc-checksums.md`.

No protocol, Rust source, zome, package cryptography or licence gate changed.
See the investigation report for configuration rationale, known unresolved
risks, same-authenticated-WAV standard-player comparison and speaker retest.
The final installer SHA-256 and packaging evidence are recorded below.


## Installer and preservation evidence

- Private installer: `dist/HolochainMusic-1.0.0-rc3-windows-x64.exe` — 42,125,787 bytes.
- SHA-256: `4593bf5e754227d01ffeb33779b5ada4aa2a7578c5dc35e94f09cb8d2d465644`.
- SHA-256 sidecar and per-file `.contents.sha256` are beside the installer.
- Built-installer packaging: PASS 11/11 (2.179 s), including candidate identity,
  overwrite refusal, required components, no private data/ASIO and user-data
  preservation rules. Runtime install/execution remains Windows-only.
- Final contents manifest vs source: PASS all 49 application files and bundled
  rc3 investigation/retest report. Raw logs in `dist/rc3-validation/`.
- NSIS 3.10, freshly compiled C launchers, `SOURCE_DATE_EPOCH=1793978394`.
  Cached inputs: `/mnt/holochain/tmp/hm-win-{upstream-0.7.0,python,wheels}`;
  all upstream/runtime/wheel SHA-256 pins verified. See the required
  `HM_WIN_*` variables in `packaging/windows/build-windows.sh`.
  `MAKENSIS=/mnt/holochain/tmp/hm-nsis/root/usr/bin/makensis`,
  `NSISDIR=/mnt/holochain/tmp/hm-nsis/root/usr/share/nsis`.
  Existing candidates cannot be overwritten. Byte reproducibility not remeasured.
- Original Windows installer rechecked unchanged:
  `cac3b97bdea6287806259130a0298d37436684cd7691f041b7baf1190b253479`.
- Windows rc2 rechecked unchanged:
  `5a72ffc7d58c2afb8e9f952dba266ea2c561970b213cbe2c5c78b973ccf0ff21`.
- Ubuntu rc1 rechecked unchanged:
  `5462eacfba8af0300fd3cf50db24df6b092235c99e842b856badb87a204467eb`.
- Existing Ubuntu worktree status unchanged; tests used disposable generated
  libraries. No user identity, grant, downloaded music or conductor state reset.
  This turn's native build caches and generated storage-node lockfile removed;
  current tested Linux MoQ helper retained at `/tmp/hm-rc3-linux-moq`.

Everything remains local/private. No push, merge, tag or publication occurred.
Physical crackling resolution and the same authenticated-WAV comparison in a
standard Windows player remain PENDING human speaker verification.
