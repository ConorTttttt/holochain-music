# Release dependency inventory and package obligations (Agent 4)

**Prepared:** 17 November 2026, main bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637. **Status: PARTIAL INVENTORY / COMPLIANCE BLOCKED.** This is a verified *declared/packaging-input* inventory, not a complete, legally signed-off transitive bill of materials. Verify every component against the exact candidate's emitted files before public distribution.

## What actually goes in each proposed package

| Component | Version / provenance seen in repo | Linux .deb | Windows NSIS | Licence/required follow-up |
|---|---|---|---|---|
| Original Python, UI, artwork, CLI and docs | current Git commit | Copied under /usr/lib/holochain-music/python and /usr/share/doc | Copied under python and docs | Original-code licence **NOT DECIDED**. Avoid labelling all files Apache-2.0 before authorisation. |
| Inter WOFF2 UI fonts (4 weights) | holochain_music/ui/fonts/Inter-OFL.txt | Copied by package script | Copied by package script | **SIL OFL-1.1**: preserve copyright and complete licence with fonts in both installers. Present in Python tree but not separately indexed in Linux copyright notices. |
| holochain | 0.7.0 declared; Linux local binary not checksum-pinned | Bundled from PATH/HOLOCHAIN_BIN | Official 0.7.0 Windows release asset pinned SHA-256 | **CAL-1.0**; full notice and exact corresponding source, build configuration, plus user-autonomy/key-export determination by counsel. |
| hc | 0.7.0 declared; Linux binary unpinned | Bundled | Official pinned 0.7.0 asset | **Apache-2.0**, confirm exact crate and dependency notices/source. |
| kitsune2-bootstrap-srv | Linux historical 0.5.1; Windows from Holochain 0.7.0 release | Bundled local binary | Pinned release asset | **Apache-2.0** declared; confirm exact version/build/metadata and transitive obligations, do not assume Linux==Windows. |
| lair-keystore.exe | conductor embeds lair | Not separately installed | Not separately installed | Separate executable **not bundled**. Embedded lair crates and related source are part of conductor's transitive inventory; identity backup autonomy unresolved. |
| music_app_bridge | music-e2e/Cargo.toml pins holochain_client 0.9.0, holo_hash 0.7.0 | Bundled release Rust executable | Bundled Windows Rust executable | Own licence undecided; transitive **colored MPL-2.0**, **inferno CDDL-1.0** as identified in historical audit; verify versions/file modifications, notices, corresponding source for each target. Other native-linked crates to inventory. |
| holochain-music-moq | crates/moq-music/Cargo.toml pins holochain-moq git rev ccd9a8e313bc588490a49adbd432964fdc6d0a3e; moq-transport 0.16.5; moq-native-ietf 0.10.0 | Bundled | Bundled | Own licence undecided; holochain-moq reports MIT OR Apache-2.0 but separate upstream LICENSE is still missing in prior audit. Other crates include webpki 0.22.4 (ISC-style); verify. |
| music_storage and music_catalogue WASM / holochain_music.happ | dna/ and music-dna/ lockfiles; hdk 0.7.0, hdi 0.8.0 | Bundled hApp | Bundled hApp | **CAL-1.0** in SDK dependencies; counsel to decide applicability, combined-work exception and corresponding source/build instructions. |
| holochain-storage-node | crates/storage-node/Cargo.toml declares MIT OR Apache-2.0 | **NOT copied** by build-deb.sh | **NOT copied** by build-windows.sh | Build/test-only in current package scripts; do not inflate shipped inventory with it. Its standalone licence and missing independent Cargo.lock in main remain a reproducibility concern for other build modes. |
| cryptography | Linux apt dependency python3-cryptography, floor >=41; Windows wheel 47.0.0 | **System dependency, NOT bundled** | Bundled Python wheel + OpenSSL | Apache-2.0 OR BSD-3-Clause; include its wheel licence, OpenSSL and notices; validate version actual shipped, not Linux floor. |
| CPython embed runtime | Python 3.14.10 pinned archive | NOT bundled | Bundled runtime | PSF-2.0 and included upstream LICENSE.txt third-party components (OpenSSL, libffi, SQLite, zlib etc.); retain complete text. |
| cffi | 2.1.1 pinned Windows wheel | Not bundled | Bundled | MIT-0: keep dist-info licence and inventory. |
| pycparser | 3.12 pinned Windows wheel | Not bundled | Bundled | BSD-3-Clause: keep copyright, disclaimer and licence. |
| sounddevice | 0.5.6 pinned Windows wheel | Not bundled | Bundled | MIT; preserve wheel licence. |
| PortAudio | 19.7 non-ASIO DLL from sounddevice | Not bundled (ALSA uses system aplay) | Bundled libportaudio64bit.dll | PortAudio MIT-style text. Confirm no ASIO-enabled DLLs survive packaging. |
| Microsoft VC runtime | VCRUNTIME140 copied from CPython embed | Not bundled | Copied into runtime and bin | **Microsoft licence review pending**; confirm permitted redistribution and exact copies. |
| MinGW-w64 compiled launchers | build-windows.sh uses mingw-w64 or supplied prebuilt launchers | Not bundled | Bundled EXEs | Confirm runtime/object-library licences and corresponding attribution for actual linked objects. |
| NSIS 3 installer | tool used to assemble | Not applicable | Compiled stub | Confirm applicable NSIS zlib/libpng attribution for shipped stub; existing audit says none required in output but legal to verify. |

### Pinned Windows third-party source input hashes

The current input pin file packaging/windows/inputs.sha256 contains:

- holochain Windows asset: 5d9bd8cf28c45645158d56198cfec38d04ac4cf620ba89ca37db2f7c46d7b3d2
- hc Windows asset: 643ed26e84a7ae72a454bd78b9427b50883fb1306406ba7b5fa4857c61c6b322
- kitsune2-bootstrap-srv Windows asset: 5c9c4b9d45f5045b517da877f0ba2237b2afc28e8f5a1f3ca659ef2d9cad1e6c
- python-3.14.10-embed-amd64.zip: 90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159
- cryptography 47.0.0 wheel: f5c3296dab66202f1b18a91fa266be93d6aa0c2806ea3d67762c69f60adc71aa
- cffi 2.1.1 wheel: 3222ba5d678f80a030e6afbcc33dc1ae5cb45facabb61cee2c7016b8432fde48
- pycparser 3.12 wheel: a076f3f489b39b43ed13563a1dafe42447445bec2e294154ec5c57fcdda4c85e
- sounddevice 0.5.6 wheel: 7f4162f514f007b0bf25a3ccfed3f1705bc2ec311888a90232729eec4f57a4f4

Pins apply to fetched inputs, NOT to reproducibility of Rust binaries, their transitive sources, or the resulting installer. The new package must record its own SHA-256 independently.

## Exact per-platform licensing/source deliverables (not yet present)

**Linux .deb** — candidate must install, at minimum, /usr/share/doc/holochain-music/copyright containing approved original-code copyright/licence and complete accurate bundled-component details, plus any required upstream licences/copyright/NOTICE/attributions. Supply versioned CAL-1.0 conductor source and exact native dependency/modified-file source, any MPL/CDDL material and build instructions. The proposed notice is in packaging/proposed-notices/ and **is not installed by build-deb.sh**. Include a CycloneDX/SPDX SBOM and SHA-256 manifest accompanying the distributed .deb. Debian policy requires a copyright file: https://www.debian.org/doc/debian-policy/ch-archive.html.

**Windows NSIS** — keep licenses/THIRD-PARTY.txt, existing upstream CAL, Apache and PortAudio texts, CPython LICENSE and each wheel's dist-info licences; add complete Rust transitive attributions and Inter OFL text in the licences area; publish the matching source correspondence, SBOMs and installer per-file SHA-256 manifest. Validate Microsoft/MinGW terms, ASIO omission, and precise release identifier. Proposed text is **not** sufficient for final shipment. Never silently replace the existing private-test banner before approval.

**Both platforms** — preserve full upstream copyright notices/conditions and source licences, track exact versions plus source archive digests, annotate static vs dynamic linking, and verify generated binary contents. Include per-DNA corresponding sources and cargo lockfiles. The project must independently decide if CAL requires key-export changes and cannot treat a source URL as satisfying all autonomy obligations.

## Required reproducible evidence collection (release engineer)

1. Freeze approved Git SHA, the complete exact build command/environment (including SOURCE_DATE_EPOCH, target, cargo/rustc/Python/NSIS/MinGW versions, features, patch sources, custom env vars), hashes of all input executables, lockfiles and hApp/WASM.
2. For each of dna, music-dna, music-e2e, crates/moq-music (and for crates/storage-node if ever shipped), run locked target-specific Cargo metadata and SBOM generation with a pinned cargo-cyclonedx version. For example, from each workspace: cargo metadata --locked --format-version 1 > metadata.json, then cargo cyclonedx --all-features (confirm CLI options of pinned tool). **Resolve features and target platform per shipped build, not only all-features; attach both when materially different.**
3. For the Linux conductor/hc/bootstrap binaries, locate original upstream lockfiles and exact build provenance and generate an independent inventory covering *their* transitive crates. This is missing for locally installed binaries and cannot be reconstructed reliably from our own lockfiles alone.
4. For Windows capture the full CPython embedded licence bundle; package METADATA/RECORD and licence files from each installed wheel; static OpenSSL/libsodium/PortAudio and runtime DLL identities; create Windows-specific SBOM(s) (CycloneDX/SPDX) cross-referenced to each staged file.
5. Generate text attributions from the **exact** resolved graph (e.g. cargo-about with a reviewed configuration); inspect unknown, dual-licensed, non-SPDX and source-file exceptions (especially MPL/CDDL/CAL). Reconcile the generated list against the actual /usr/lib/holochain-music/bin and NSIS bin/runtime directories.
6. Stage notices, licence texts, corresponding-source archives and machine-readable SBOMs; verify paths using dpkg-deb -c or an NSIS extraction, and hash all evidence. Independently review every attribution and record the release/legal reviewer decision in docs/release-licensing-decision-record.md.

**Blocker:** Neither the current Linux assembly script nor current Windows attribution file produces the complete required collection. A historical 6 November SBOM is useful background but not verifiable evidence for this commit's proposed packages.
