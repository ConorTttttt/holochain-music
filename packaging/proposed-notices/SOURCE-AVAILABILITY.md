# Proposed source-availability information (UNAPPROVED, INCOMPLETE)

This is a **template**, not a current offer of corresponding source. It does not authorise distribution and should not be shipped with empty fields. In particular, CAL-1.0 contains obligations beyond a generic repository link; independent legal review must approve the exact method and duration of providing source, build instructions and user data/keys.

Candidate/version: [PENDING OWNER APPROVAL]
Commit: [FULL SHA]
Linux package basename, bytes, SHA-256: [MISSING]
Windows installer basename, bytes, SHA-256: [MISSING]
Matching hApp and embedded DNAs: [SHA-256 EACH]
Date, distribution audience and country: [MISSING]
Source access URL or physical media / request contact, retention and response SLA: [LEGAL REVIEW]
Owner/legal signature and dated applicability: [MISSING]

## Exact corresponding-source mapping to complete

| Shipped object | Corresponding-source archive/path and source SHA-256 | Build inputs/configuration required |
|---|---|---|
| Linux holochain 0.7.0 executable | [VERIFY ACTUAL BUILT SOURCE TREE & GIT TAG/COMMIT] | [LOCKFILE, ALL DEPENDENCIES, BUILD FLAGS, PATCHES, TOOLCHAIN, REPRODUCIBILITY] |
| Windows holochain 0.7.0 official executable | [VERIFY OFFICIAL ASSET CORRESPONDENCE] | [UPSTREAM SOURCE, ASSET HASH, PATCHES/RECIPE, TOOLCHAIN] |
| hc and kitsune2-bootstrap-srv for each OS | [EXACT SOURCE FOR EACH VERSION] | [BUILD FLAGS + LOCKFILES + LICENCE/NOTICE] |
| Both compiled DNA WASM and hApp | [PROJECT COMMIT + SDK TREE/HASHES + LOCKFILES] | [WASM TARGET, hc tooling, bundling recipe, feature list] |
| music_app_bridge Linux/Windows | [PROJECT COMMIT + ALL TRANSITIVE SOURCE; MPL/CDDL MODIFIED FILES IF ANY] | [CARGO LOCK/FLAGS, OPENSSL/LIBSODIUM STATIC INPUTS] |
| holochain-music-moq Linux/Windows | [PROJECT COMMIT + HOLOCHAIN-MOQ GIT REV + LOCKFILES] | [MoQ/QUIC TARGET, TRANSITIVE SOURCE, TOOLCHAIN] |
| Windows CPython and wheels, OpenSSL, runtime DLLs, PortAudio, launchers | [UPSTREAM EXACT ARCHIVES/LICENCE TEXTS] | [WINDOWS INPUT SHA-256, DLL PROVENANCE, NSIS/MINGW INPUTS] |
| Inter font | [MATCH CURRENT BUNDLED FONTS TO INTER RELEASE/COMMIT] | [COPY FONT LICENCE AND COPYRIGHT] |

## Recipient's data, keys and autonomy

The application keeps audio, grants and various keys locally and supports encrypted backups/WAV export, but the historical audit states the conductor's lair agent key is **not included in app backups**. Counsel and the product owner must decide if CAL-1.0's user-autonomy requirements demand additional identity/key export, migration or written procedures. Record a test of a recipient's independent use of own data and necessary keys, not merely a statement that the source is available. Do not export lair private keys into public evidence.

Approval status: **BLOCKED — source archives, corresponding build inputs, complete legal scope and autonomy evidence not yet recorded.**
