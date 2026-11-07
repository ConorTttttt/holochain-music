# Windows test installer checksums (unsigned, private testing only)

Written after the build; not inside the package.

| | |
|---|---|
| File | `HolochainMusic-1.0.0-rc-windows-x64.exe` (42,124,441 bytes) |
| **SHA-256** | `cac3b97bdea6287806259130a0298d37436684cd7691f041b7baf1190b253479` |
| Built from | commit `ce13bbd` on `feat/v1-windows-port`, `SOURCE_DATE_EPOCH=1793978268` |
| Reproducibility | two builds from the same inputs: byte-identical |
| Builder | Ubuntu 26.04 host, NSIS 3.10, mingw-w64 (binutils 2.45.90), Rust 1.99.0 |
| `holochain-music-moq.exe` input | `5060e0e90b9cdc84a4bde8f186ddf1578f936584c3fadffeb0a47c021b601e30` (cross-built, `x86_64-pc-windows-gnu`) |
| `music_app_bridge.exe` input | `c12cc1e5f36099b71aef0a7768275c13bfe3578fe45a59a3286d63df29e5f86f` (cross-built; libsodium from the crate source, portable) |
| Third-party inputs | pinned in `packaging/windows/inputs.sha256` |
| Per-file checksums | `dist/HolochainMusic-1.0.0-rc-windows-x64.contents.sha256` (also `SHA256SUMS.txt` inside the install folder) |

Verify on Windows: `Get-FileHash .\HolochainMusic-1.0.0-rc-windows-x64.exe -Algorithm SHA256`.
The local file is `/mnt/holochain/holochain-music-win/dist/`. It has not been published or sent anywhere.


## Private WASAPI recovery candidate — 1.0.0-rc2 (2026-11-06)

| | |
|---|---|
| File | `HolochainMusic-1.0.0-rc2-windows-x64.exe` (42,092,776 bytes) |
| **SHA-256** | `5a72ffc7d58c2afb8e9f952dba266ea2c561970b213cbe2c5c78b973ccf0ff21` |
| Built from | base `877664c766b1445743769fb6376c43c60b51286b` plus local WASAPI recovery changes on `feat/v1-windows-port`; not committed or pushed |
| `SOURCE_DATE_EPOCH` | `1793978394` |
| MoQ helper input SHA-256 | `5060e0e90b9cdc84a4bde8f186ddf1578f936584c3fadffeb0a47c021b601e30` |
| Bridge helper input SHA-256 | `efac845be570a336a531a6a5326427f108c9f38ee167938690dba204e9f23202` (portable static libsodium, existing documented MinGW build configuration) |
| Per-file checksums | `dist/HolochainMusic-1.0.0-rc2-windows-x64.contents.sha256`; packaged application files match the final source |
| Checksum sidecar | `dist/HolochainMusic-1.0.0-rc2-windows-x64.exe.sha256` |
| Validation | `windows-wasapi-rc2-validation.md`; physical Windows speaker retest pending |

Verify on Windows:

```powershell
Get-FileHash .\HolochainMusic-1.0.0-rc2-windows-x64.exe -Algorithm SHA256
```

The original Windows installer above and the existing Ubuntu rc1 `.deb`
remain unchanged. This new unsigned installer is local and private; it has not
been published. Quit the old app before upgrading in place; retain its user
data, identities and library. Retest with `--audio wasapi` using
`windows-wasapi-rc2.md`.


## Private audio-quality candidate — 1.0.0-rc3 (2026-11-06)

| Item | Value |
|---|---|
| File | `HolochainMusic-1.0.0-rc3-windows-x64.exe` (42,125,787 bytes) |
| SHA-256 | `4593bf5e754227d01ffeb33779b5ada4aa2a7578c5dc35e94f09cb8d2d465644` |
| Version | `1.0.0rc3` |
| Status | Automated validation passed; physical Realtek and identical-WAV Windows-player comparison PENDING |
| Per-file checksums | `dist/HolochainMusic-1.0.0-rc3-windows-x64.contents.sha256` |
| Sidecar | `dist/HolochainMusic-1.0.0-rc3-windows-x64.exe.sha256` |
| Investigation / speaker retest | `windows-wasapi-rc3.md` |
| Validation / changed files | `windows-wasapi-rc3-validation.md` |

```powershell
Get-FileHash .\HolochainMusic-1.0.0-rc3-windows-x64.exe -Algorithm SHA256
```

Quit the old app and upgrade in place; keep existing identities/settings,
grants and downloaded music. Original Windows, Windows rc2 and Ubuntu rc1
installer hashes were rechecked unchanged. No publication is authorized.
