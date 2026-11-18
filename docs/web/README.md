# Holochain Music in the browser (experimental)

**Status: experimental development track. Not released, not deployed, not part
of the v1.0.0 desktop release candidate.** The desktop application and its DNAs
are unchanged by this work.

A listener opens Holochain Music in Chromium, gets a persistent Holochain
identity from the Holo Web Conductor (HWC) extension, browses the real Music
catalogue published by native artists, verifies the artist's signed encrypted
package and its hosts, and plays authorised audio decrypted inside the browser.

## What works today (verified in real Chromium against native Music)

| Checkpoint | Status | Evidence |
| --- | --- | --- |
| A — browser connects (HWC identity, exact Music DNAs, authenticated gateway) | **PASS** | interop checks A1–A3 |
| B — native artist publishes, browser discovers (browse, search, artist page) | **PASS** | B1–B3, C1 |
| C — browser receives the genuine signed manifest, host receipt and ciphertext | **PASS** | C2 |
| D — browser verifies and plays the actual Music audio | **PASS, with an out-of-band grant** | D1–D4 |
| E — artist issues a grant over Holochain to the browser | **BLOCKED** | E1 — HWC/H2HC have no `call_remote` |
| F — fresh profile completes the documented flow unaided | **NOT MET** | needs E |

Checkpoint D uses a genuine v1 licence signed with the native artist's real key
and encrypted to the browser's own recipient key, but it reaches the browser as
a file (operator-assisted), not through Holochain private delivery. It is not
claimed as Checkpoint E. See [grants.md](grants.md) for the exact blocker and
the proposed fix.

## Documents

- [setup.md](setup.md) — run it, build HWC, provision the gateway, connect native participants, reproduce tests
- [architecture.md](architecture.md) — components, decisions, media transport
- [security.md](security.md) — trust boundaries, what the browser verifies, remaining vulnerabilities
- [grants.md](grants.md) — grant compatibility, the private-delivery blocker and the interoperability proposal
- [integration-tests.md](integration-tests.md) — test matrix and evidence
- [roadmap.md](roadmap.md) — next steps and prompts for follow-up agents

## Pinned components

| Component | Version |
| --- | --- |
| Music DNAs (unchanged source, Holochain 0.7.0 `hc`) | `music_catalogue` `uhC0k6tJ5iJFWusUqhJjjt0crDBsW7AhwRqzXhDeMf6reThaN7Uqn`, `music_storage` `uhC0kkLUOg2uytGWLz_sTeVtfJBqa0criBmAYAPwAIUhoDp_9G4RV` (from this environment's toolchain; the test always compares browser vs native) |
| Holo Web Conductor | `Holo-Host/holo-web-conductor@0c391226e78769d44ccb4661881ed8998b15f903` + Imposter browser-alpha patches + Music multi-cell routing patch |
| Imposter baseline | `followup/browser-alpha-final-acceptance@a39aaf926ebcc2aadad71ee4bba0b7c2677de67f` (contains `release/browser-alpha-rc1@0b58e5a`) |
| H2HC gateway | accepted Imposter revision-2 `h2hc-linker`, SHA-256 `8f3f8e0b6a6fc02b27776182458cf0d970bc02f76db9f6f6b6842c04f138746f`, source `9f5eb04b5be12e3e9e7fcc304bd905da1449ade9` |
| Holochain | 0.7.0 release binaries (`hc`, `holochain`, `lair-keystore`, `kitsune2-bootstrap-srv`) |

All pins are machine-readable in [`web/hwc/pins.json`](../../web/hwc/pins.json).
