# Agent 9 — outstanding feature branches and post-RC1 UX triage

Audit: **2026-11-17**. Source of truth: `main` at **`bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637`**. This is a read-only code/PR/CI audit plus an integration plan; **no application tests or manual two-device tests were run as part of this audit**. PR metadata, diffs, branch ancestry and selected GitHub Actions job logs were inspected. This document must be revalidated if `main` advances.

Integration follow-up, **2026-11-17**. Music PRs #9–#22 were closed after `git merge-base --is-ancestor` confirmed all 14 exact heads are in `main` through the [v1 integration merge](https://github.com/ConorTttttt/holochain-music/commit/c7aec4d318cdf3275fb1af03ef7443db3f2b6385). Closure comments link to that commit. The feature branches and their review history remain available.

## Decision

**Do not merge historical draft branches wholesale, redesign the player, or change audio licence/grant semantics to reduce the PR count.** Protect the RC1 branch; deliver independent post-RC1 changes from an up-to-date baseline through reviewable, independently tested PRs.

Current `main` contains the v1 music application, S1 encrypted CAS and S2/S4/S5–S18 music pipeline, Holochain/MoQ playback, the bottom player, Inter, Phosphor icons, Ocean Signal and Amethyst themes, local-only PNG album artwork, collection-first Library, playlists, verified offline library / WAV export and guarded storage removal. It does **not** yet include PR #38 peer-artwork delivery, PR #39 layered Now Playing UI, or PR #23's decision-management UI. Do not confuse existing local album artwork with peer-distributed artwork.

## Branch/PR disposition

| PR(s) | Evidence and current disposition | Next action |
|---|---|---|
| #4 (S1), #8 (S5) | Merged; historical foundations | Retain closed |
| #5 (early S2) | Closed as superseded by the v1 integration merge after comparing the agent-binding implementation and the replacement WASM and integrity checks | Use the current v1 implementation |
| #6–#7 (early S3/S4) | Open, divergent from `main`. #6 retains standalone audit and repair code. #7 retains distinct local secret-file ignore rules | Preserve the branches for separate review |
| #9–#22 (S5 integration through S18) | Closed as already integrated. All 14 exact heads are ancestors of `main` through the v1 integration merge | Use the historical PRs and their linked tests for reference |
| #25 (UI semantic controls) | Open divergent trial; current theme/control implementation is newer | Compare residual changes; close as superseded if no independently useful behaviour remains |
| #28 (Plus Jakarta Sans) | Closed as superseded by the locally bundled Inter typography in #35 | Keep the historical trial branch available |
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

## Agent 9 execution addendum — ancestry, CI and review disposition

Rechecked **2026-11-17**, baseline `main` = [`bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637`](https://github.com/ConorTttttt/holochain-music/commit/bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637). This addendum verifies **each** original S9–S22 branch head, not just representative examples. These checks use GitHub's `compare/<historical-branch>...main` ancestry API. No feature code was rebased or run; the evidence records branch history, **not** new physical acceptance.

### Exact historical S-series ancestry / proposed PR closure record

Every row below returned `status=ahead`, `behind_by=0`: `main` contains the exact PR head commit as an ancestor. The follow-up above records the closures. The following table preserves the evidence and proposed wording from the original audit.

| Historical PR | Head commit contained in current `main` | Proposed close note |
|---|---|---|
| [#9](https://github.com/ConorTttttt/holochain-music/pull/9) | [`864e895`](https://github.com/ConorTttttt/holochain-music/commit/864e895984ad9f790ee23f4618dbeeea91b66899) | Integrated in `main`; preserve verified S5→S2→S4 retrieval history |
| [#10](https://github.com/ConorTttttt/holochain-music/pull/10) | [`c9ba6ac`](https://github.com/ConorTttttt/holochain-music/commit/c9ba6aca8d474522e4d82764cbeebb5932af7583) | Integrated; conductor bridge |
| [#11](https://github.com/ConorTttttt/holochain-music/pull/11) | [`e398508`](https://github.com/ConorTttttt/holochain-music/commit/e398508f299445fb6179ce36b09096b35a4d6f8d) | Integrated; live verified retrieval |
| [#12](https://github.com/ConorTttttt/holochain-music/pull/12) | [`7b6916a`](https://github.com/ConorTttttt/holochain-music/commit/7b6916a0ef5634c5c916aee339a89e0d0b04b644) | Integrated; MoQ ciphertext transport |
| [#13](https://github.com/ConorTttttt/holochain-music/pull/13) | [`b047038`](https://github.com/ConorTttttt/holochain-music/commit/b0470387b0863f5063f8ec0b65075f3fe9c4de54) | Integrated; authenticated endpoint |
| [#14](https://github.com/ConorTttttt/holochain-music/pull/14) | [`30fb1ad`](https://github.com/ConorTttttt/holochain-music/commit/30fb1adc5415fbdbeaa24b4d97a76fb3bc1397b9) | Integrated; owner-granted WAV |
| [#15](https://github.com/ConorTttttt/holochain-music/pull/15) | [`5765ddb`](https://github.com/ConorTttttt/holochain-music/commit/5765ddb2c18b44c16ea7d0b33e3501a8e74ce824) | Integrated; ALSA buffering |
| [#16](https://github.com/ConorTttttt/holochain-music/pull/16) | [`b079783`](https://github.com/ConorTttttt/holochain-music/commit/b07978339900463dcde184ffa4c61ca99c7ae18e) | Integrated; streaming overlap |
| [#17](https://github.com/ConorTttttt/holochain-music/pull/17) | [`a0dc1c2`](https://github.com/ConorTttttt/holochain-music/commit/a0dc1c218f61c8aff978bdce19b722705642404b) | Integrated; jitter adaptation |
| [#18](https://github.com/ConorTttttt/holochain-music/pull/18) | [`d443d47`](https://github.com/ConorTttttt/holochain-music/commit/d443d476066537d12b61919401af3113b46af36c) | Integrated; repair and seek |
| [#19](https://github.com/ConorTttttt/holochain-music/pull/19) | [`ebc8892`](https://github.com/ConorTttttt/holochain-music/commit/ebc88925156d7fc69fb6769a91d2d548451b5168) | Integrated; selective MoQ repair |
| [#20](https://github.com/ConorTttttt/holochain-music/pull/20) | [`9443286`](https://github.com/ConorTttttt/holochain-music/commit/94432866c359e19abc08c603f81e5341a2a0b581) | Integrated; in-flight seek |
| [#21](https://github.com/ConorTttttt/holochain-music/pull/21) | [`4805d99`](https://github.com/ConorTttttt/holochain-music/commit/4805d997813cafda5d35f0fe8d474311978262d0) | Integrated; pinned private LAN |
| [#22](https://github.com/ConorTttttt/holochain-music/pull/22) | [`0ac4687`](https://github.com/ConorTttttt/holochain-music/commit/0ac4687ef30c69809bc0cb113668f66e99e6f307) | Integrated; local authorised player |

The original audit found divergent heads for [#5](https://github.com/ConorTttttt/holochain-music/pull/5), [#6](https://github.com/ConorTttttt/holochain-music/pull/6), [#7](https://github.com/ConorTttttt/holochain-music/pull/7), [#25](https://github.com/ConorTttttt/holochain-music/pull/25), [#28](https://github.com/ConorTttttt/holochain-music/pull/28) and [#29](https://github.com/ConorTttttt/holochain-music/pull/29). The disposition table above records the subsequent source comparisons and closures.

**Suggested closure comment for an ancestry-proven PR:** “Closing as integrated into `main`: the exact historical head `<SHA>` is an ancestor of current `main` `bd7aabc` (GitHub compare: `behind_by=0` from historical head to main). Historical commits and regression tests remain traceable through the PR and repository. No re-merge is required. Post-RC1 follow-up work is tracked in PR #53.”


### Historical acceptance-evidence lookup (retain when closing #9–#22)

These are **existing source/test pointers on main**, not freshly executed assertions. Each closure comment should link its historical PR/head commit above **and** the relevant test/doc location below. Reviewers must consult each PR's original test log and the current CI result before making any stronger “verified operationally” claim.

| PR | Current-main regression / design evidence pointers |
|---|---|
| #9 | [catalogue tests](../tests/test_music_catalogue.py), [storage validation](../tests/test_storage_validation.py), [S5 retrieval design](s5-s2-s4-integration.md) |
| #10 | [live conductor tests](../tests/test_live_conductor.py), [S6 design](s6-live-conductor-bridge.md) |
| #11 | [S7 fixture tests](../tests/test_s7_fixture.py), [S7 design](s7-live-end-to-end.md) |
| #12 | [S8 transport tests](../tests/test_s8_moq.py), [S8 design](s8-moq-encrypted-transport.md) |
| #13 | [S9 endpoint tests](../tests/test_s9_moq.py), [S9 design](s9-holochain-moq-endpoint.md) |
| #14 | [S10 grant/audio tests](../tests/test_s10_granted_audio.py), [S10 design](s10-granted-wav-playback.md) |
| #15 | [S11 buffering tests](../tests/test_s11_buffered_playback.py), [S11 design](s11-buffered-alsa-playback.md) |
| #16 | [S12 streaming tests](../tests/test_s12_streaming_playback.py), [S12 design](s12-playback-while-moq-arrives.md) |
| #17 | [S13 jitter tests](../tests/test_s13_adaptive_playback.py), [S13 design](s13-adaptive-moq-jitter.md) |
| #18 | [S14 repair tests](../tests/test_s14_seek_repair.py), [S14 design](s14-verified-cas-repair-seek-replay.md) |
| #19 | [S15 selective recovery tests](../tests/test_s15_selective_moq_repair.py), [S15 design](s15-selective-moq-quic-repair.md) |
| #20 | [S16 in-flight seek tests](../tests/test_s16_inflight_seek.py), [S16 design](s16-inflight-moq-seek.md) |
| #21 | [S17 pinned-LAN tests](../tests/test_s17_lan_moq.py), [S17 design](s17-private-lan-moq.md) |
| #22 | [S18 local player tests](../tests/test_s18_local_player.py), [S18 design](s18-local-authorised-music-player.md) |

A current-main Storage protocol workflow [completed successfully](https://github.com/ConorTttttt/holochain-music/actions/runs/44074316970) at this audit; that single result must **not** be reported as a successful run of the above complete matrix. New CI is pending on this documentation PR.

### Updated feature conflict and implementation evidence

- **#38 signed peer artwork:** `holochain_music/artwork_transport.py` and `tests/test_artwork_transport.py` are added only on its branch. The current `main` uses `albumArtworkUrl(albumId)` for **local-only** art; old #38 changes it to `albumArtworkUrl(albumId, artistAgent)`. Main's `ui/app.js` is now approximately **922 lines** versus **542 lines** on the old #38 branch. Port this API/call-site and validated transport/controller paths selectively; never replace the current JS, playback, offline, playlist, or collection implementation. Preserve independent album-author and S2 signer verification, endpoint/certificate pinning and revalidation of offline cache; test public visibility with no audio grant.
- **#39 Now Playing:** Main's `ui/app.js` already contains `applyPlayer`, `lastSeq`, `pendingSeek`, `requestSeek(frame)`, `renderPlayer()`, queue, playlist and offline-control handlers. Old PR adds a side panel/dialog, `renderLayers()` and focus handlers. Keep these as **view-only projections**, not a second player or remote API. The old `server.py` syntax correction is already on main. PR #39 currently reports `mergeable=false`; do not merge wholesale.
- **#23 request decisions:** Main `ArtistService` has `requests()` and `grant()` but no `reject()` or `decide_batch()`. Old PR uses a local atomic decision ledger, reentrant request lock, explicit 1–25 hashes per batch and partial-result reporting. Its single-request and bulk decisions need replay/idempotency/queue-delivery and kind-immutability testing on the **current** grant code before port; declines must not revoke a prior grant.
- **#24 metadata/DNA:** The old PR changes `dna/`, `music-dna/`, the native bridge, request reply protocol and public DHT cover entries. No subset that modifies DNA may be adopted until versioned schema, backward compatibility, package migration and the conflict with #38's MoQ artwork model are agreed.

### CI evidence snapshot (not a fresh test run)

| Source/head | Observed workflow status from GitHub Actions | Interpretation |
|---|---|---|
| `main` `bd7aabc` | Several completed **successful** Storage protocol push runs; another Storage protocol run **queued** at this audit | Does not establish all release gates |
| PR #53 `0077594` | v1 application, Windows port and Storage protocol runs **queued** | Documentation branch has **no concluded CI** in this snapshot |
| PR #38 `f7311d6` | v1 application, Storage protocol, Windows port, catalogue/storage integration: **failed** | Old CI fails; no current-baseline integrated acceptance |
| PR #39 `4b2b43e` | v1 application and Storage protocol **succeeded**; integration **cancelled**; Windows **failed** | Old-head partial green is insufficient |
| PR #23 `61b6818` | v1 application and Storage protocol **succeeded**; integration **cancelled** | Old-head partial green is insufficient |
| PR #24 `2c49f1c` | v1, catalogue, Sweettest, storage and integration workflow runs **succeeded** on the **old stacked DNA** | No migration or current-main compatibility proof |

These statuses were read from the respective GitHub Actions workflow runs on 2026-11-17; queued and cancelled are neither successes nor failures. The earlier #38 failure classifications described above remain diagnostic hypotheses tied to selected logs; no new failing code was executed in this audit.

### Ready-for-implementation backlog and merge gates

| Sequence | Independent proposed PR (from a **fresh current-main branch**) | Dependencies / mandatory gate | Status as audited |
|---|---|---|---|
| P2-A | **Now Playing presentation only**, port #39's panel/dialog and adapted static tests; do not copy old state handlers | Canonical `applyPlayer` / seek / queue; current JS syntax and UI regression checks; actual keyboard, screen reader, zoom and physical audio | **Not implemented on current main; blocked on selective port** |
| P2-B | **Signed peer artwork**, port #38's public package / resolver / app endpoint and artist-scoped UI calls; no DNA change | Signed provenance, manifest pin, MoQ host/TLS verification, offline cache tamper rejection; **physical Alice/Bob two-device test required** | **Not implemented on current main; live acceptance NOT RUN** |
| P2-C | **Artist request inbox decisions**, port #23 server, ledger and filters in isolation | Exact requested kind, stale/duplicate request and existing-grant invariants; persistent file permissions; max-25 partial results, accessible confirmations | **Not implemented on current main** |
| P2-D | **Versioned metadata migration design** for #24; no production migration | Pick MoQ-versus-DHT artwork model, additive DNA types, old-app/hApp compatibility and rollback, two-conductor matrix | **Blocked on architecture decision** |
| P2-E | Future artwork replacement/global cache eviction and additional album/genre UI | Versioned album revisions and explicit cache bounds | **Deferred** |

A full runnable [Alice/Bob artwork acceptance runbook](post-rc1-artwork-two-device-acceptance.md) supplies required evidence IDs, rejection cases and pass/fail capture. A successful unit test alone is **not** a substitute for the two-device demonstration.

### Agent 9 execution status / residual risks

- **GitHub inspections actually performed:** latest main, PR #53/#38/#39/#23/#24 metadata and patches, code paths, each #9–#22 ancestry comparison, divergent branch checks, selected CI run metadata.
- **Tests actually run by this agent:** **none**. Shell access to the remote GitHub checkout and suitable physical conductors/devices was not available through this execution environment. Earlier contributors' PR test claims and CI runs are listed as *previous evidence*, not this agent's executions.
- **Changed files in this PR:** this triage document and the linked two-device acceptance runbook only. No Holochain identities, DNAs, audio grants, MoQ trust roots, signed manifests, user data, UI, or player code was changed.
- **Recommended next maintainer action:** review these closure recommendations; then create **separate** main-based feature PRs only after suitable local tooling and hardware test slots are available. Explicitly preserve draft status until all merge gates pass. Do not merge PR #53 into RC1 as a feature.
