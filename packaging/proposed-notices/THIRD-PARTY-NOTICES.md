# HOLOCHAIN MUSIC — PROPOSED THIRD-PARTY NOTICES (INCOMPLETE)

**DRAFT / NOT FOR DISTRIBUTION IN THIS FORM.** Candidate Git SHA: [TO BE FILLED]. Package and architecture: [TO BE FILLED]. Package SHA-256: [TO BE FILLED]. Owner/legal review and sign-off: [MISSING]. Any original-code licence is undecided; this document does not assert one.

## Linux .deb — actually bundled or embedded

| Location / component | Licence identified so far | Required notice/source work |
|---|---|---|
| bin/holochain (declared 0.7.0) | CAL-1.0 | Include unmodified authoritative CAL text + existing copyright notices, exact binary build source/lockfiles, build instructions and user-data/key-autonomy compliance plan. |
| bin/hc (declared 0.7.0) | Apache-2.0 | Include authoritative Apache-2.0 text + upstream NOTICE/copyright, exact binary transitive inventory. |
| bin/kitsune2-bootstrap-srv (historical 0.5.1) | Apache-2.0 | Verify actual built version and provenance; same notices/transitive inventory. |
| bin/music_app_bridge | original-code licence NOT decided; dependencies include MPL-2.0 colored, CDDL-1.0 inferno | Generate exact locked/target dependency inventory; preserve relevant MPL/CDDL notices and make required corresponding source available, including modified files if any. |
| bin/holochain-music-moq | original-code licence NOT decided; holochain-moq git ccd9a8e3…; moq-transport =0.16.5, moq-native-ietf =0.10.0 | Confirm upstream licence file, each transitive licence (e.g. webpki ISC-style), complete notices and source. |
| holochain_music.happ (storage/catalogue DNAs) | SDKs hdk =0.7.0, hdi =0.8.0: CAL-1.0 | Legal decision on compiled work/exception; provide source/lockfiles/notices as approved. |
| python/holochain_music/ui/fonts/inter*.woff2 | SIL OFL-1.1 | Preserve Inter copyright 2020 and **complete** holochain_music/ui/fonts/Inter-OFL.txt licence in /usr/share/doc/holochain-music/ and with the fonts. |
| Other copied application Python and UI | Licence NOT decided | Owner approves licence and copyright; third-party code review required. |

**Not copied into Linux .deb:** system python3-cryptography, ALSA/aplay from alsa-utils (APT dependencies), standalone crates/storage-node binary and any standalone lair-keystore executable. They must not be misleadingly described as installed files. Any libraries statically linked into bundled native binaries **do** belong in those binaries' SBOM.

## Windows NSIS — additionally bundled

| Location / component | Licence identified | Required notice/source work |
|---|---|---|
| Official Holochain 0.7.0 EXE assets | CAL-1.0 for conductor; Apache-2.0 for hc/bootstrap declared | Verify SHA-256 against packaging/windows/inputs.sha256; full upstream licence/NOTICE/corresponding source and autonomy legal decision. |
| runtime CPython embed 3.14.10 | PSF-2.0 + third-party components | Ship full upstream runtime/LICENSE.txt including bundled OpenSSL, SQLite, libffi, zlib and other upstream notices. |
| cryptography wheel 47.0.0 (includes OpenSSL 3) | Apache-2.0 OR BSD-3-Clause | Preserve cryptography-47.0.0.dist-info/licenses and any bundled OpenSSL notices. |
| cffi 2.1.1 | MIT-0 | Preserve wheel licence from dist-info. |
| pycparser 3.12 | BSD-3-Clause | Preserve exact copyright text and licence. |
| sounddevice 0.5.6 | MIT | Preserve licence and wheel attribution. |
| non-ASIO PortAudio 19.7 | PortAudio MIT-style | Preserve existing PortAudio-LICENSE.txt and confirm ASIO variants absent. |
| VCRUNTIME140.dll in runtime and bin | Microsoft redistributable code | Legal reviewer must verify redistribution terms for the **actual copied DLLs**. |
| MinGW-w64 C launchers | Runtime/licence to confirm | Audit linked runtime licences and any copied headers/objects/attribution. |
| NSIS stub | NSIS zlib/libpng-style | Confirm licence requirements applicable to emitted stub. |
| Rust apps/hApp/Inter fonts | as Linux rows | Windows target-specific lockfiles/features, static OpenSSL/libsodium and fonts must be covered by notices/source and SBOM. |

Existing packaging/windows/THIRD-PARTY.txt and licenses/ texts contain some of this material, but the Rust transitive attribution and other legal decisions are incomplete.

## Texts and notices to place alongside approved notices

Copy **verbatim from the exact upstream release/component source**, do not paraphrase:

- CAL-1.0 complete text and notices for Holochain + applicable SDK code.
- Apache-2.0, including any upstream NOTICE files, for covered crates/binaries.
- MPL-2.0 and CDDL-1.0 complete texts, copyright notices and source provisions for relevant file-level components.
- Every other transitive binary licence including MIT/BSD/ISC, named contributors and exceptions where required.
- SIL OFL-1.1 complete Inter font licence and copyright.
- CPython 3.14.10 full LICENSE.txt, bundled third-party attributions; exact wheel licences; PortAudio licence.
- Owner-approved original-code licence/NOTICE, after L01 approval.

**PLACEHOLDER — DO NOT DISTRIBUTE:** Rust lockfile dependency graphs with package name/version/source URL/commit, SPDX expression, component hash, linked binary and copied copyright/NOTICE text: [GENERATE FROM APPROVED BUILD]. Corresponding-source offer details: [COMPLETE packaging/proposed-notices/SOURCE-AVAILABILITY.md]. CycloneDX/SPDX SBOM names/hashes: [PENDING]. Owner/legal signature: [PENDING].
