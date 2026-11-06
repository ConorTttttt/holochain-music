# Private Windows rc2 validation — 2026-11-06

Built locally on Ubuntu from `feat/v1-windows-port`, base commit
`877664c766b1445743769fb6376c43c60b51286b` plus the uncommitted WASAPI fix.
The source changes, tests, CI step and private installer remain local.

## Results

| Check | Result |
|---|---|
| Complete Linux Python suite, including real local MoQ/QUIC and storage tests | PASS: 348 tests in 130.641 s, 13 skipped |
| New WASAPI lifecycle regression module | PASS: 26 tests, including COM balancing, process-MTA lifetime ordering and authenticated Player paths |
| Built installer packaging tests | PASS: 11/11; identifier preservation and overwrite refusal included |
| Final application source vs installer contents manifest | PASS: all 49 application files and rc2 investigation/retest report match |
| Linux ALSA null seek benchmark, licensed 5:31 generated track, 20 seeks | Baseline and fixed both median 2.4 ms, p95 2.7 ms; zero timeouts, backward-position anomalies or static-position stalls |
| Existing 5-minute null-player seek regression, 15 seeks | PASS: median 0.8 ms, p95 1.1 ms; verifies once per open and checks every emitted chunk |
| Windows MoQ release cross-build, locked/offline | PASS (`x86_64-pc-windows-gnu`) |
| Windows MoQ Rust tests compile (`--no-run`) | PASS; Windows executables built, not executed on Linux |
| Windows bridge release cross-build, locked/offline | PASS with existing portable static libsodium input |
| Windows installer | PASS: NSIS 3.10, pinned upstream/runtime/wheel digests, freshly cross-compiled C launchers, complete candidate identifier |
| Python syntax, shell syntax, existing UI script syntax, diff whitespace | PASS |
| Windows native CI | Added conditional real WASAPI smoke; not run (no push authorized) |
| New build on physical Windows speakers | PENDING USER RETEST |

The 13 Linux-suite skips are seven opt-in real-conductor flow/grant-security
tests, four Windows-only DACL/Job Object/audio tests, and two built-installer
tests. The two packaging tests were subsequently enabled and passed in the
11-test installer validation. Native WASAPI/COM behavior is instrumented on
Linux; cross-compilation does not execute Windows or validate speakers.
The real-conductor opt-in suite was not rerun for this output-only fix.

The new tests cover forward/backward seek, track switch, concurrent repeated
seeks, seek/stop/play, open/start failure/retry, failed-seek retry, device loss,
EOF drain cancellation, concurrent abort/native stop, callback failure,
native stop/abort/close failure, PCM worker startup failure, delayed teardown
retry, canceled verification, COM balancing, process-MTA lifetime pinning/release
ordering, failed-import retry and network shutdown despite an
audio error. Instrumented streams reject overlapping lifetimes and native
calls from different threads, assert callback/owner/PCM-worker termination,
and compare delivered PCM digests against the real authenticated reader.
A native close failure remains an explicit ownership error requiring app
restart; a driver that never returns cannot be recovered safely in-process.

## Reproduction

```bash
HOLOCHAIN_MOQ_BIN=<Linux MoQ binary> \
HOLOCHAIN_STORAGE_NODE_BIN=<Linux storage-node binary> \
  python3 -m unittest discover -s tests -v

HM_WIN_INSTALLER_CONTENTS=$PWD/dist/HolochainMusic-1.0.0-rc2-windows-x64.contents.sha256 \
  python3 -m unittest discover -s tests -p test_windows_packaging.py -v

cargo build --locked --offline --release --target x86_64-pc-windows-gnu \
  --manifest-path crates/moq-music/Cargo.toml
cargo test --locked --offline --target x86_64-pc-windows-gnu --no-run \
  --manifest-path crates/moq-music/Cargo.toml
(cd music-e2e && SODIUM_LIB_DIR=/mnt/holochain/tmp/hm-sodium-mingw/install/lib \
  CARGO_TARGET_DIR=target-win cargo build --locked --offline --release \
  --target x86_64-pc-windows-gnu --bin music_app_bridge)

python3 packaging/bench-seek.py --seconds 331 --seeks 20 --interval 0.2 \
  --device null --json /tmp/hm-wasapi-alsa-fixed.json
```

The default bridge cross-build encountered the already documented prebuilt
libsodium/MinGW runtime mismatch (`memset_explicit` undefined). The successful
command uses the existing crate-source-built portable library configured with
`ac_cv_func_memset_explicit=no`, without `--enable-opt`/`-march=native`.
No Rust dependency, cryptographic implementation or zome was changed.

Installer inputs are pinned in `packaging/windows/inputs.sha256`. The build
used `SOURCE_DATE_EPOCH=1793978394`, the cached upstream files under
`/mnt/holochain/tmp/hm-win-{upstream-0.7.0,python,wheels}`, the Windows helpers
above, and `/mnt/holochain/tmp/hm-nsis/root/usr/bin/makensis` with
`NSISDIR=/mnt/holochain/tmp/hm-nsis/root/usr/share/nsis`.
Run `packaging/windows/build-windows.sh <new-empty-output-directory>` with the
`HM_WIN_*` inputs documented at the top of that script. It refuses to replace
an existing candidate or contents manifest. The final installer supersedes a
never-shared temporary build from before the final MTA lifetime review. Byte reproducibility was not remeasured for rc2.

Local raw logs and benchmark JSON: `dist/rc2-validation/`.

## Installer and preserved artefacts

- New: `dist/HolochainMusic-1.0.0-rc2-windows-x64.exe`, 42,092,776 bytes.
- New SHA-256: `5a72ffc7d58c2afb8e9f952dba266ea2c561970b213cbe2c5c78b973ccf0ff21`.
- Original Windows installer unchanged: `cac3b97bdea6287806259130a0298d37436684cd7691f041b7baf1190b253479`.
- Original Ubuntu `holochain-music_1.0.0~rc1_amd64.deb` unchanged: `5462eacfba8af0300fd3cf50db24df6b092235c99e842b856badb87a204467eb`.

No user identity, library or conductor data was reset. Tests used disposable
synthetic libraries; the existing Linux worktree changes remain unchanged.
No push, merge, publication or existing Ubuntu artefact modification occurred.
See `windows-wasapi-rc2.md` for the required Windows speaker retest and log path.
