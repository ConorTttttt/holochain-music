# RC3 source / provenance ledger — DRAFT (2026-11-17)

This is the **pre-build** ledger. It records inspected source and
existing CI evidence, **not a new package build**. Future package-specific
provenance JSON and SHA-256 files are emitted by
`packaging/rc-build.sh` / `packaging/rc-evidence.py`, then reviewed and
linked here. Do not fabricate or copy hashes from the historical packages.

## Inspected source

| Field | Observed |
|---|---|
| Repository | `ConorTttttt/holochain-music` |
| Main at audit | `bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637` |
| Python version (pyproject + package) | `1.0.0rc3` |
| Final integrated tested SHA | **PENDING: Agents 1/2 + RC preparation merge** |
| Final Git tree SHA and SOURCE_DATE_EPOCH | **PENDING: exact final commit** |
| Public release/tag/upload permission | **NOT GRANTED** |

## Existing CI evidence — not transferable to the final SHA

| Workstream | Source commit | CI run | Actual result |
|---|---|---|---|
| Windows fixes (PR #45) | `c4b89f21f43e78278ffb4b120af31a3a9541326d` | `43581953080` | **PASS:** Windows-native, hApp bundle, NSIS installer and Windows installed-app smoke |
| Real-conductor split (PR #46) | `5ddab122d500c05b08e7099d0c70bc367a23479e` | `43574405481` | **PASS:** four Sweettest groups and Python/Rust/Node |
| Integrated RC3 SHA | **PENDING** | **PENDING** | **NOT RUN** |

Windows installer CI uploads at PR-head commit are useful evidence of the
pre-integration workflow; their artifact ZIP digests are **not**
SHA-256 of the final RC installer. They must not be represented as such.

## Planned final-build evidence (all absent until a real build)

| Property | Ubuntu 26.04 amd64 .deb | Windows 11 x64 NSIS |
|---|---|---|
| Filename | `holochain-music_1.0.0~rc3_amd64.deb` | `HolochainMusic-1.0.0-rc3-windows-x64.exe` |
| Exact source commit | **PENDING** | **PENDING** |
| Full package SHA-256 | **PENDING — NO FILE** | **PENDING — NO FILE** |
| Contents / major binary hashes | **PENDING — NO FILE** | **PENDING — NO FILE** |
| SOURCE_COMMIT.txt inside installed files | **NOT VERIFIED** | **NOT VERIFIED** |
| Builder image / toolchain | **NOT RECORDED FOR FINAL BUILD** | **NOT RECORDED FOR FINAL BUILD** |
| Upstream input hashes | **REVIEW REQUIRED** | Source pin list exists, final input validation pending |
| Repeat assembly SHA-256 match | **NOT RUN** | **NOT RUN** |
| Package installation and smoke | **NOT RUN** | **NOT RUN ON FINAL SHA** |
| Speaker/LAN/physical hardware | **BLOCKED** | **BLOCKED** |

## Existing historical hashes (archive references only)

- Ubuntu November 6 RC1 .deb (`958b23d`):
  `5462eacfba8af0300fd3cf50db24df6b092235c99e842b856badb87a204467eb`.
- Private Windows November 6 RC3 installer:
  `4593bf5e754227d01ffeb33779b5ada4aa2a7578c5dc35e94f09cb8d2d465644`.
  Its checksum document does **not** provide an independently verified final
  build-source commit for this exact historical RC3 file.

These values are retained for auditing old packages and **must not appear
in the new artefact checksum sidecars** unless a freshly built file actually
matches byte-for-byte, which has not been established.

After integrated CI is green, populate this ledger using real
`*.provenance.json`, `*.sha256`, tested installer and actual runner logs.
Physical speaker/LAN testing, legal review, private-grant security sign-off and
owner distribution approval remain independent gates. Details:
[RC3 release-candidate plan](rc3-release-candidate-plan.md).
