# Owner/legal decision record — proposed release licence and CAL-1.0

**Decision status: OPEN / NOT APPROVED** — prepared 17 November 2026 against main bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637. This is not legal advice, not the owner's consent, and not an authorisation to add a LICENSE file or distribute any package.

## L01 — Licence for original Holochain Music work

**Proposal for consideration:** Apache License 2.0 for the original Python code, application services, UI, project-specific native helper/bridge code, zomes, documentation and packaging (subject to appropriate authors' rights and third-party provenance). The repository currently has no top-level LICENSE. One existing crate, crates/storage-node/Cargo.toml, already declares **MIT OR Apache-2.0**; do not silently overwrite that expression. Source origin, contributions, fonts/icons and any reused components must be checked individually.

**Decision required from owner and counsel:** approved licence (or split licence by component) ____; copyright owners/years ____; third-party code exclusions ____; is project-specific NOTICE required ____; authorisation to add licence identifiers ____; dated signature ____.

If declined: select another licence before release. If approved: implement approved texts and accurate SPDX metadata in a separately reviewed code/metadata change; never infer approval from this proposal.

## L02 — CAL-1.0 Holochain conductor and autonomy

The Linux .deb assembly copies locally supplied holochain, hc and kitsune2-bootstrap-srv binaries from PATH without verifying their hashes. Its historical report identifies **holochain 0.7.0** as CAL-1.0. Windows uses SHA-256-pinned official Holochain 0.7.0 release assets. The exact Linux binary provenance remains to be established for each new candidate.

Counsel must decide (a) whether to bundle the conductor or make it an external prerequisite, (b) how to provide complete corresponding source/build inputs and required notices for exact shipped binary, (c) whether any extra CAL terms apply to the distributed combination and (d) the practical user-data and key autonomy obligations, including conductor/lair identity keys not currently in app encrypted backups. A link to a tag is not automatically proof that it corresponds to the exact shipped binary.

The CAL-1.0 text includes access-to-source and user-autonomy requirements; verify these against the authoritative licence text and the actual distribution model: https://opensource.org/license/CAL-1.0 and https://spdx.org/licenses/CAL-1.0.html.

**Legal decision:** bundle / external prerequisite / other ____; scope and notices ____; corresponding source delivery method and retention ____; data/key export remedies ____; approver/date ____.

## L03 — CAL-1.0 HDK/HDI inside shipped Wasm

Both dna/Cargo.toml and music-dna/Cargo.toml pin **hdk = 0.7.0** and **hdi = 0.8.0**. Their code is compiled into the shipped hApp. Counsel must examine the exact dependency source files' notices, whether any combined-work exception applies, how licensing attaches to application-authored zomes, and corresponding source/build material for each DNA. Do **not** assume blanket copyleft, blanket exemption, or Apache compatibility merely from dependency names.

**Legal decision:** licence per zome/DNA ____; applicable exceptions and source-level evidence ____; required disclosures ____; reviewer/date ____.

## L04 — Redistributed Rust/source notices and SBOMs

The bridge's observed dependency inventory in docs/licensing-audit.md lists **colored (MPL-2.0)** and **inferno (CDDL-1.0)** transitively. Confirm their exact locked versions, source files, any modifications and exact distribution obligations. A package-wide blanket source offer is insufficient without exact component/version/source mapping and reviewer approval. Include Inter's **SIL OFL-1.1** font text, already present at holochain_music/ui/fonts/Inter-OFL.txt. Inventory and proposed nonfinal notices: docs/release-dependency-inventory.md and packaging/proposed-notices/.

**Decision:** full transitive inventory reconciled to BOTH actual installers and system-linked libraries Y/N ____; correct corresponding source verified Y/N ____; SPDX/CycloneDX review Y/N ____; reviewer/date ____.

## L05 — Windows-specific redistribution

Windows bundles CPython **3.14.10**, pinned wheels cryptography **47.0.0**, cffi **2.1.1**, pycparser **3.12** and sounddevice **0.5.6**, PortAudio **19.7** without ASIO DLLs, and copies Visual C++ runtime beside upstream executables. Check the *actual* CPython licence bundle and all embedded DLL/CRT restrictions. Existing documentation also flags MinGW-w64 runtime attribution and NSIS licensing. Confirm official upstream assets and all wheel licences from the exact cached archives rather than relying only on declared SPDX strings.

**Decision:** MSVC redistributable rights ____; MinGW runtime obligations ____; DLL licence and attribution completeness ____; installer notice completeness ____; reviewer/date ____.

## Owner/independent legal reviewer sign-off — deliberately blank

- Candidate Git SHA, package basenames + SHA-256:
- Jurisdictions/distribution model, including whether private beta distribution is contemplated:
- L01: APPROVE / REJECT / REQUEST CHANGES (detail):
- L02: APPROVE / REJECT / REQUEST CHANGES (detail):
- L03: APPROVE / REJECT / REQUEST CHANGES (detail):
- L04: APPROVE / REJECT / REQUEST CHANGES (detail):
- L05: APPROVE / REJECT / REQUEST CHANGES (detail):
- Project owner (identity, UTC timestamp, signature/record link):
- Legal reviewer (identity, professional role, UTC timestamp, signature/record link):
- Conditions, deadlines and evidence archive links:

**Default until valid sign-off: BLOCKED.** No package distribution, licence metadata changes, or public tag are authorised by this record.
