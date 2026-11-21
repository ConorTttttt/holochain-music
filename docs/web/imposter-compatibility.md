# Imposter browser work: compatibility assessment for Music

Assessed 2026-11-21 from GitHub (fetched heads, branch ancestry and file
diffs). All heads equal the previously observed SHAs.

| Branch | Head | Base (merge-base with Music baseline) | Verified CI |
| --- | --- | --- | --- |
| `followup/browser-alpha-final-acceptance` (Music baseline) | `a39aaf9` | — | (baseline) |
| `feature/firefox-android-hwc` (PR #10) | `968c6e1` | `c92353c` (lacks 4 baseline commits: gateway archive, operator runbook — docs/tooling only) | [44428605059](https://github.com/ConorTttttt/imposter-holochain/actions/runs/44428605059) |
| `feature/browser-full-gameplay` (PR #11) | `88632f1` | `c92353c`, contains the Firefox work | [44545282579](https://github.com/ConorTttttt/imposter-holochain/actions/runs/44545282579) |
| `feature/repeatable-browser-lobbies` (PR #12) | `12ea762` | `c92353c` | [44578422397](https://github.com/ConorTttttt/imposter-holochain/actions/runs/44578422397) |
| `integration/repeatable-browser-lobbies-firefox` | `41b8572` | `c92353c`, Firefox + lobbies | [44579828513](https://github.com/ConorTttttt/imposter-holochain/actions/runs/44579828513) |

The CI links are the ones recorded by the Imposter branches; they were not
re-run in this round.

## Does any of it implement standard `call_remote`?

**No.** Every branch keeps `call_remote` forbidden in the installed-cell
runtime (`hwc-installed-runtime.mjs`: `forbidden=[…'call_remote']`, and
`trusted-receiver.test.mjs` asserts the guest service has no `call_remote`).
`docs/hwc-confidential-full-round-transport-proposal.md` explicitly states
that native↔HWC remote-call interoperability is a separate, unimplemented gate.
The game's private channel (`role_request_v1`/`role_delivery_v1`, domain
`imposter.h2hc.private-role.v1`) is a typed, game-specific, HPKE-encrypted
relay; it is not a general remote call and is not used by Music.

## Classification

| Change | Where | Generic / game-specific | Affects | Compatible with Music baseline | Decision |
| --- | --- | --- | --- | --- | --- |
| Firefox Desktop HWC patch (`private-role/firefox-desktop.patch`): background-owned WebSocket wired to the installed role receiver, `manifest.firefox.json`, worker changes | PR #10, #11, integration | Generic transport plumbing + game role wiring | **HWC** (websocket-service, base/firefox executors, background, ribosome-worker) | Yes: applies cleanly on top of Imposter's three patches, and Music's routing, record-verification and new call_remote patches apply on top of it (checked locally) | Not merged into Music's Chromium build. Music ships a separate `remote-call/firefox-binding.patch` for the Firefox executor (see below) |
| `build-firefox-extension.sh`, `package-firefox.py` | PR #10 | Generic build tooling | HWC build | Yes | Reused as the reference for a Firefox build; not vendored |
| Mixed Chromium/Firefox harness (`ci/alpha-operator/mixed-browser*.{mjs,py}`) | PR #10, #11 | Harness is generic, checks are game-specific | none (tests) | n/a | Lessons only (profile restart with Mozilla temporary add-on storage settings, Geckodriver) |
| Gameplay UI, movement/chat relay (`ui/src/browser/*`, `movement-relay.cjs`) | PR #11 | **Game-specific**; relay is a separate Node service with transient, player-supplied data | none (not in HWC or H2HC) | n/a | **Not used.** Different trust model; Music grants stay on `call_remote` + private inbox |
| Repeatable lobbies: `native-repeatable.patch` (game DNA), `apply_browser_lobbies.py` (HWC background lobby selection), store changes | PR #12, integration | **Game-specific**; changes the game DNA identity | HWC background (game zome names only), game DNA | Not applicable to Music | **Not ported** |
| Repeatable-session lessons: persistent identity across restart, selecting the authenticated record, replay reservations across sessions, reconnect only to the configured gateway | PR #12, integration | Generic lessons | — | — | Applied as Music tests R1–R3, G4 and the persistent nonce witness |
| Gateway | all branches | — | **H2HC** | All branches still use the accepted pinned gateway (`8f3f8e0b…`) unchanged | Music's candidate gateway is separate (see below) |

## What Music took

* **HWC:** nothing copied. The new call_remote code is browser-independent
  (`packages/core/src/remote-call/*`, shared `ribosome-worker.ts`); only the
  last hop differs: Chromium uses the offscreen document
  (`offscreen/index.ts`), Firefox uses the background executor
  (`firefox-binding.patch`, applies on top of Imposter's Firefox patch).
  Neither binding exposes a new privileged message to pages.
* **H2HC:** the candidate is the accepted source (reproduced from Imposter's
  recipe `293563649f…`, source tree `46122443…`) plus `web/gateway/call-remote.patch`.
  Imposter role relay files and domain separation are untouched; the only
  shared edits are additive (new capability variants, new WS frame types, an
  exception to the 8 KiB frame limit for `call_remote_response` only).
* **Tests:** restart/recovery and isolation checks modelled on the repeatable
  lobby work (R1–R3, I1–I2, G4).

## Not executed in this round

* Imposter mixed Chromium/Firefox acceptance and repeatable-lobby acceptance
  against the candidate gateway (they need Imposter's game hApp build,
  Firefox + Geckodriver; neither Firefox nor Geckodriver is available in this
  container). The gateway's Imposter role relay is covered by its Rust tests
  (unchanged and passing in the candidate build); live Imposter regressions
  remain **NOT RUN**.
