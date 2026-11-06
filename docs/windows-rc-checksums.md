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
