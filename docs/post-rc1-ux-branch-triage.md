# Agent 9 — outstanding feature branches and post-RC1 UX triage

Audit: **2026-11-17**. Source of truth: `main` at **`bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637`**. This is a read-only code/PR/CI audit plus an integration plan; **no application tests or manual two-device tests were run as part of this audit**. PR metadata, diffs, branch ancestry and selected GitHub Actions job logs were inspected. This document must be revalidated if `main` advances.

## Decision

**Do not merge historical draft branches wholesale, redesign the player, or change audio licence/grant semantics to reduce the PR count.** Protect the RC1 branch; deliver independent post-RC1 changes from an up-to-date baseline through reviewable, independently tested PRs.

Current `main` contains the v1 music application, S1 encrypted CAS and S2/S4/S5–S18 music pipeline, Holochain/MoQ playback, the bottom player, Inter, Phosphor icons, Ocean Signal and Amethyst themes, local-only PNG album artwork, collection-first Library, playlists, verified offline library / WAV export and guarded storage removal. It does **not** yet include PR #38 peer-artwork delivery, PR #39 layered Now Playing UI, or PR #23's decision-management UI. Do not confuse existing local album artwork with peer-distributed artwork.

## Branch/PR disposition

| PR(s) | Evidence and current disposition | Next action |
|---|---|---|
| #4 (S1), #8 (S5) | Merged; historical foundations | Retain closed |
| #5–#7 (early S2/S3/S4) | Open, divergent from `main`; function areas have since been implemented, but branch ancestry does **not** prove every original change is present | Inspect any unique security/protocol differences, then close as **superseded** with cross-reference to current code; never merge blindly |
| #9–#22 (S5 integration through S18) | Open historical drafts. GitHub `compare/<branch>...main` returns `ahead` with `behind_by=0` for representative stack heads, including S5→S4 retrieval, S6–S11, S17 and S18. S18 head `0ac4687` is an ancestor of `main` (44 commits ahead) | Close remaining drafts as **integrated/superseded** after checking no active review blockers; link back to `main` history and tests. Do not remerge |
| #25 (UI semantic controls) | Open divergent trial; current theme/control implementation is newer | Compare residual changes; close as superseded if no independently useful behaviour remains |
| #28 (Plus Jakarta Sans) | Open divergent font trial; current accepted UI uses locally bundled **Inter** via merged #35 | Close as superseded; do not reintroduce competing font |
| #29 (Phosphor icon trial) | Open divergent trial; Phosphor implemented through merged #30/#33 | Close as superseded after residual-diff check |
| #30–#37 (UI and local artwork) | Closed/merged: Phosphor, Ocean Signal, appearance, v1 integration, Amethyst, Inter, player polish, local PNG art | Retain closed; avoid duplicate implementation |
| #40–#42 (Library/offline/storage) | Closed/merged; present on `main` | Retain closed; maintain library and verified-readiness contracts |
| **#38** `feat/artwork-moq-distribution` | Open **draft**, divergent (21 ahead / 9 behind as audited). Added 11 files, ~928 insertions / 124 deletions versus old base. Still missing live two-device MoQ artwork acceptance | **Repair/rebase selectively, verify, merge only after separate acceptance**; do not combine with #39 or #24 |
| **#39** `design/layered-now-playing-v1` | Open **draft**, currently `mergeable=false`, divergent (15 ahead / 9 behind). 5 files touch server/UI/tests | **Port only presentation changes** onto current player in separate PR; preserve one engine/session/queue and current UI additions |
| **#23** `feat/artist-request-bulk-decisions` | Open **draft**, stacked on `feat/v1-app-integration`, divergent (10 ahead / 24 behind); request filters, decline ledger, bounded batch actions and 7 tests | **Extract targeted request-management work** into a new main-based, post-RC1 PR; separately verify races, idempotency and existing grant semantics |
| **#24** `feat/artist-albums-artwork-genres` | Open **draft**, stacked on #23, divergent (58 ahead / 24 behind); edits both `dna` and `music-dna`, UI, private-request protocol, and public DHT artwork | **Defer / decompose**. First agree on versioned album/track metadata and hApp/DNA migration; reconcile conflicting DHT-artwork approach with #38 before implementation |
| #43 (offline pause/resume/retry) | Independent open draft and Agent 8's responsibility | Keep separate from UX triage |

Open PR is **not** evidence of missing code. Use merge ancestry, current source and tests; do not bulk-close a divergent branch solely because filenames exist on main.

## PR #38 — artwork review and acceptance gate

Current implementation (reviewed via `holochain_music/artwork_transport.py`, `catalogue.py`, `app.py`, browser UI and tests):
- New album v1 entry pins SHA-256 of the artist-S2-key-signed S1 manifest, not raw PNG bytes. Derive a **public** domain-separated artwork file ID/wrapping key from artist agent + album ID. Never reuse audio keys or claim confidentiality.
- Listener resolves authenticated Holochain author/key/file commitment, replica claim, host receipt and pinned TLS MoQ endpoint before accepting bounded ciphertext chunks. Decrypt/authenticate chunks; require scrubbed bounded PNG. No audio licence needed to view **public** artwork.
- A verified artist-separated cache persists signed-manifest/ciphertext evidence; re-check on offline read. At most two concurrent fetch jobs; browser handles HTTP 202 and falls back to vinyl.
- Original v1 albums with `artwork_manifest_sha256: null` cannot acquire remote artwork by simply republishing the same album ID; need versioned updates later.
- Review remaining lifecycle concerns: retry/cooldown and host fallback after 202, cache size/global eviction, refresh/recovery after offline errors, metadata-root pin model and artist host availability. Confirm that optional artwork failure never interrupts audio.

**Observed CI at #38 head `f7311d6`:** `v1 application`, storage unit, Windows port and music catalogue storage integration runs failed. The inspected Python/storage/integration logs identify `SyntaxError: '{' was never closed` in `holochain_music/server.py`'s font static-asset allowlist (a pre-existing bug now corrected on `main`). Windows failed building vendored OpenSSL due to its Perl environment. The failures are **not evidence that signed artwork itself failed its unit tests**, but the branch still has **no passing current-baseline full CI**. Do not mark green based on the branch's reported 74 focused tests from 2026-11-07.

**Required real two-device acceptance (blocker):** Alice and Bob are separate conductor identities/profiles/devices with working pinned MoQ; Alice publishes a **new** album with clean PNG and a track; Bob discovers the album and sees the cover **without an audio grant**, offline restart displays the previously verified cache, and corrupt chunk / mismatched artist / wrong album / invalid receipt / wrong TLS fingerprint are all rejected without playback interruption. Include inaccessible host, network loss, explicit LAN opt-in and a genuinely uncached offline case. Record logs/evidence and test Windows/Linux packaging where relevant.

Run on the rebased feature PR:
```sh
python3 -m compileall -q holochain_music music_catalogue holochain_storage
python3 -m unittest discover -s tests -p 'test_album_artwork.py' -v
python3 -m unittest discover -s tests -p 'test_artwork_transport.py' -v
python3 -m unittest discover -s tests -p 'test_artwork_catalogue.py' -v
python3 -m unittest discover -s tests -p 'test_ui_player_polish.py' -v
node --check holochain_music/ui/app.js
```
Also require current-baseline full Python/Rust/MoQ/conductor/Windows CI gates relevant to the changed paths, not only these isolated checks.

## PR #39 — minimal Now Playing conflict-resolution plan

`mergeable=false` on 2026-11-17; do **not** blindly merge or reset `holochain_music/ui/app.js`, `index.html` or `app.css` to the old PR. The PR adds an optional fixed right-hand side panel, read-only queue, and native expanded dialog while delegating play/pause, next, seek and volume to the existing bottom-player actions. The current `main` has since gained library/offline/playlist features and their event handlers. The PR's 1-line server syntax fix is **already present on main**; drop it when porting.

On a fresh branch based on current `main`:
1. Preserve the single `MusicApp.player`, `state.player`, `state.queue`, `applyPlayer` sequence filtering, `pendingSeek` coalescing and `requestSeek` confirmation model. Add **view-only** layered DOM/handlers, not a second audio element, API, queue or state machine.
2. Port panel/dialog HTML and CSS as the smallest self-contained changes. Preserve current playlists, collection UI, offline controls, theme selectors, typography and browser blob artwork loading. No external album-art URL.
3. Merge `renderLayers()` into the **current** `renderPlayer()` without replacing existing status/seek/queue handling. Keep button delegation to the current canonical controls; true “Previous Track” must not be fabricated (back = 10 seconds).
4. Fix/recheck focus: panel trigger, right-edge tab, close/Escape, dialog close, queue navigation and fallback focus if an opener is removed. The expanded queue route currently closes the dialog and navigates; its `close` event may restore focus back to the old trigger after navigation. Verify and resolve ordering.
5. Test keyboard seek/drag cancel/blur and fast track changes (no stale expanded slider or duplicate playback). Confirm Space/Enter global shortcuts do not hijack focused buttons, input sliders or modal controls. Verify screen-reader labels/status and 200% zoom, narrow windows and all themes.
6. Include `tests/test_ui_layered_player.py` **adapted to the current UI**, not copied with assumptions from the old source. Test hidden-at-start layers, unique element IDs, canonical state and control delegation.

**Observed old-head CI:** v1 app and storage protocol runs succeeded, integration run cancelled, Windows run failed while vendored OpenSSL was configured by Perl. User-reported focused tests on old commits are not new-head verification. Physical audio, keyboard, browser and 200%-zoom tests were not observed.

Minimum checks:
```sh
python3 -m unittest discover -s tests -p 'test_ui_layered_player.py' -v
python3 -m unittest discover -s tests -p 'test_ui_player_polish.py' -v
python3 -m unittest discover -s tests -p 'test_album_artwork.py' -v
python3 -m unittest discover -s tests -p 'test_ui_library_collections.py' -v
python3 -m unittest discover -s tests -p 'test_ui_offline_library.py' -v
python3 -m unittest discover -s tests -p 'test_ui_ocean_signal.py' -v
python3 -m unittest discover -s tests -p 'test_ui_phosphor_icons.py' -v
python3 -m unittest discover -s tests -p 'test_ui_typography.py' -v
node --check holochain_music/ui/app.js
```
Broader main CI and physical Windows WASAPI/Linux audio remain separate merge gates; do not obscure audio issue #26.

## PRs #23 and #24 — artist studio

**#23 has independent useful functionality:** local 0600 decision ledger, Pending/Approved/Declined, folder/kind/status/search filters, explicit 1–25 request-hash batch operations, partial results and irreversible-licence confirmation. Current main does not have the corresponding management endpoints and UI. Re-implement as one minimal post-RC1 feature branch against main. Check stale duplicate inbox entries; single vs bulk approvals; idempotence across queued deliveries, exceptions and restarts; immutable requested kind and manifest; private request provenance; no grant revocation; keyboard operability, confirmations and partial-result announcements. Do not silently change grant types or issue new entitlement semantics. PR #23's old branch CI `v1 application` / storage succeeded but its integration run was cancelled; re-run against current main.

**#24 must not be combined with #23 or #38.** It introduces track metadata edits, album assembly and genre workflows, but also changes public music DNA + storage DNA, Rust bridge and request-decision propagation. It proposes small public DHT WebP/PNG/JPEG entries (up to 32 KiB), whereas #38 uses signed MoQ artwork outside the DHT. These are competing distribution choices, not additive “all artwork” fixes. Determine an explicit **versioned album-update and track-metadata protocol**, backwards-compatible serde/entry-link handling, installed-hApp migration path, two-conductor acceptance and shared artwork model first. Only then split into (a) metadata/album editing UI, (b) protocol/migration, (c) genres/search, and (d) any authenticated private response changes. Do not infer production compatibility from the older successful PR #24 workflows.

## Post-RC1 UX roadmap / separate PRs

| Order | Scope | Ready-to-merge gate |
|---|---|---|
| 0 | RC1 stabilisation and release gates | Release baseline frozen; avoid drawing unverified feature PRs into RC1 |
| 1 | Layered Now Playing (#39) **if** its conflict port is isolated | Current UI tests, browser/screen-reader/keyboard/200%-zoom, no second player, real audio check |
| 2 | Signed peer artwork (#38), can be developed in parallel | Latest CI plus real two-device signed MoQ, host-failure and offline-tamper proof |
| 3 | Artist request decisions (#23) | Ledger/concurrency/grant-security regressions, current CI and accessible workflows |
| 4 | Versioned artist albums/track metadata, genre search (#24) | Protocol design, DNA/hApp migration, two-conductor tests; separate from artwork transport |
| 5 | Optional improvements | Artwork cache eviction and versioned cover replacement, artwork format conversion; product decision separately |

Order 1 versus 2 can swap based on test readiness. Neither is an RC1 gate. Other open security/Windows/media-core/offline work has separate owners and must not be swept into a UX merge.

## Accessibility and validation matrix

For every proposed UI integration, verify with mouse **and keyboard alone**: Tab/Shift+Tab order, Enter/Space on controls, no hidden focus, Escape closing, focus restoration, form labels, disabled and busy states, live-status announcements, visible focus indicators, seek range keyboard input, 200% browser zoom, narrow viewport reflow, light/dark/Amethyst contrast and reduced-motion. Use a real browser/screen reader; static tests and `node --check` are not substitutes.

## Change management

This document is itself **documentation-only**. No feature branch was merged, closed or modified and no successful test runs are claimed. Close superseded PRs in separate administrative actions after their review notes are recorded. Create one separately reviewable implementation PR per feature; do not rewrite original historical feature branches and do not reset the release baseline.
