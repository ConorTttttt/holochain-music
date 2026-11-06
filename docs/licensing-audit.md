# Licensing audit (v1.0.0-rc1) — NOT legal advice, NOT final

Status: **draft for the owner's decision and legal review.** No licence has been
applied to the repository. Sources: `license` fields in the exact crate
versions in our lockfiles and the local cargo registry, plus CycloneDX SBOMs
generated with `cargo cyclonedx --all-features` (2026-11-06).

## 1. Proposal under investigation: Apache-2.0 for our original code

Apache-2.0 is compatible with the permissive licences of nearly all our
dependencies, includes an explicit patent grant, and is the licence used by
much of the Holochain networking stack (kitsune2, holo_hash, hc bundle).
Open question: whether code compiled against CAL-1.0 SDKs (§2.2) can be
distributed under Apache-2.0 alone.

Our original code: `holochain_music/`, `music_catalogue/`, `holochain_storage/`,
`crates/moq-music`, `crates/storage-node`, `music-e2e` (bridge), the zome
sources in `dna/` and `music-dna/`, the UI, docs and packaging.

## 2. Components with obligations

### 2.1 Bundled Holochain conductor binary — CAL-1.0

`/usr/lib/holochain-music/bin/holochain` is `holochain` 0.7.0, licensed
**Cryptographic Autonomy License 1.0**. Obligations to verify with counsel
before redistributing it in the `.deb`:

- Provide (or offer) the Corresponding Source of the exact version we ship,
  with its licence notice.
- CAL's user-autonomy provisions: recipients who use the software to process
  their data must be able to get their user data and the keys needed to use it
  independently. Our app keeps data and keys locally in the user's own
  directories and offers backup/export. Whether that satisfies CAL — and how it
  applies to the lair keystore holding the agent key, which v1 backups do
  **not** export — needs legal confirmation.
- Whether shipping the binary unmodified triggers obligations beyond notice and
  source availability.

Lower-obligation alternative: do not bundle the conductor. Make it a
documented external prerequisite (e.g. installed from Holochain's own
distribution) and keep our package permissively licensed.

### 2.2 Zome SDKs compiled into our DNAs — CAL-1.0

`hdk` 0.7.0 and `hdi` 0.8.0 are CAL-1.0 and are compiled into
`music_storage.dna` and `music_catalogue.dna` (both shipped inside
`holochain_music.happ`). Legal question: are our zomes derivative works that
must be distributed under CAL-1.0, or does Holochain's licensing exempt apps
built with the HDK? This decides whether the DNAs can be Apache-2.0.

### 2.3 Other redistributed binaries

| Binary | Licence of its crate | Notes |
|---|---|---|
| `hc` (holochain_cli 0.7.0, bundle crate) | Apache-2.0 | used only for first-run install; could be replaced by admin-API calls in the bridge |
| `kitsune2-bootstrap-srv` 0.5.1 | Apache-2.0 | |
| lair keystore (inside `holochain`) | MIT OR Apache-2.0 | |
| `music_app_bridge` (ours) | — | links `holochain_client` 0.9.0 (MIT), `holo_hash` (Apache-2.0), `colored` (**MPL-2.0**), `inferno` (**CDDL-1.0**) via `holochain_types`→`holochain_trace`, `libbz2-rs-sys` (bzip2-1.0.6, permissive) |
| `holochain-music-moq` (ours) | — | holochain-moq (MIT OR Apache-2.0; that repository has no LICENSE file), moq-transport / moq-native-ietf (MIT OR Apache-2.0), `webpki` 0.22.4 (ISC-style licence file) |

MPL-2.0 and CDDL-1.0 are file-level copyleft. Distributing binaries requires
making the source of those files available and keeping their notices. That is
compatible with Apache-2.0 for our own code.

### 2.4 Python

`cryptography` (Apache-2.0 OR BSD-3-Clause) is a system dependency
(`python3-cryptography`) and is **not** redistributed in the `.deb`. Standard
library only otherwise.

## 3. Gaps found

1. No `LICENSE`/`NOTICE` file in this repository or in holochain-moq.
2. The `.deb` ships third-party binaries without licence texts or a source
   offer. **It must not be distributed publicly until this is fixed.**
3. The bundled `holochain`/`hc`/`kitsune2-bootstrap-srv` binaries were built
   locally (`cargo install`) without a recorded lockfile, so their full
   transitive licence inventory is not reproducible yet. Rebuild them from
   tagged sources with `--locked` and generate SBOMs.
4. Our own crates have no `license` field (shows as UNKNOWN in the SBOM).

## 4. Recommended next steps (for approval)

1. Owner decides on Apache-2.0 for original code. If approved: add `LICENSE`,
   `NOTICE` and `license = "Apache-2.0"` fields.
2. Legal review of §2.1 and §2.2, comparing bundling the conductor with
   requiring it as an external prerequisite.
3. Add `/usr/share/doc/holochain-music/copyright` with every bundled
   component's licence text and a written source offer, plus SBOMs in the
   release.
4. Ask the holochain-moq maintainer (the same owner) to add a LICENSE file.
