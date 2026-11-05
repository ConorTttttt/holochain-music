# Holochain Music v1.0.0 — release readiness

Living document. Every "PASS" below names the command or evidence that was
actually run on the development host (HP Pro Mini 400 G9, Ubuntu, Holochain
0.7.0 native binaries, Python 3.14.4). Nothing is marked verified from
documentation or prior PR descriptions alone.

Status legend: **PASS** = executed and passed here · **FAIL** = executed and
failed · **SKIP** = test exists but was skipped · **BLOCKED** = needs hardware,
credentials or a human decision · **NOT RUN** = not yet executed ·
**MISSING** = functionality does not exist yet.

## 1. Baseline audit (2026-11-05, branch `feat/s18-local-granted-music-player` @ `0ac4687`)

### Repository and PR chain

- PR #4 (S1) is merged to `main`. PRs #5–#22 are **drafts**, each stacked on
  the previous milestone branch (S2 → … → S17 → S18). Nothing after S1 is on
  `main`. Integration requires merging the stack in order; that needs user
  authorisation.
- PR #22 (S18) CI: `manifest-contract`, `s18-local-player`, `unit (3.10/3.12/3.13)`,
  `zome`, `python-rust-node` pass; `real-conductors` was still pending at audit time.
- Local working tree of the main checkout: only a staged generated
  `music-e2e/flake.lock` plus untracked build outputs. Development continues
  in a separate worktree (`/mnt/holochain/holochain-music-v1`) so the user's
  running S18 demo is not disturbed.
- Disk: `/mnt/holochain` is 99% full (≈16 GB free). Rust target directories
  are shared rather than duplicated. This is an operational risk for
  Holochain native builds.

### Tests executed during the audit

| Suite | Command | Result |
|---|---|---|
| Full Python suite, real Rust S4 node + MoQ binaries | `HOLOCHAIN_STORAGE_NODE_BIN=… HOLOCHAIN_MOQ_BIN=… python -m unittest discover -s tests` | **PASS** 211 tests, 23 s |
| Full Python suite, no Rust binaries | `python -m unittest discover -s tests` | **PASS** 200, **SKIP** 6 (binary-dependent) |
| Previous S18 combined-run S7 fixture stall | same as above, twice | Did **not** reproduce (whole suite finished in 18–24 s) |
| `crates/moq-music` | `cargo test` | **PASS** 5 |
| `crates/storage-node` | `cargo test` | **PASS** 6 |
| Catalogue integrity zome | `cargo test -p music_catalogue_integrity --lib` | **PASS** 2 |
| Storage integrity zome | `cargo test --lib` (in `dna/`) | **PASS** 2 |
| Three-conductor Sweettests (S7, S9–S16) | `nix develop ./music-e2e --command cargo test …` | **NOT RUN** in this audit (previous runs are reported in PR descriptions only) |
| Physical ALSA speaker playback via S18 UI | manual | **BLOCKED** on user confirmation |
| Two physical computers | manual | **BLOCKED** (hardware) — and see defect D1 |

### Defects and gaps found by reading the code

| ID | Severity | Finding |
|---|---|---|
| D1 | **High (release blocker for LAN)** | `dna/integrity` `valid_moq_url` accepts only `https://127.0.0.1:<port>`. A host on a LAN cannot publish its RFC1918 MoQ endpoint to Holochain, so S17 two-machine discovery is impossible with the current DNA, independent of hardware. |
| D2 | High (product) | MoQ publisher is one-shot: one subscriber, one file, then exits; it generates a new TLS certificate on every start. A host cannot serve a catalogue or a second listener without re-publishing endpoints. |
| D3 | High (product) | No catalogue browsing from the app. The conductor bridge requires artist agent, host agent and track ID as inputs; nothing lists artists/albums/tracks for a user. The zomes already have `list_artists`, `list_tracks`, `list_albums`, `search_tracks`. |
| D4 | High (product) | No in-app grant workflow. Grants are created by test helpers with the artist's private key in the same workspace; there is no request/approve/deliver path. |
| D5 | High (product) | S10 grants have a hard 24-hour maximum lifetime (`MAX_LIFETIME_SECONDS = 86400`). "Permanent offline access" is impossible with the grant type used by every playback path. The older S1 perpetual grant (`holochain_storage/grant.py`) is not bound to Holochain agents and is unused by playback. |
| D6 | High (product) | No persistent conductor, identity or data directory management. Every multi-conductor run is an in-process Sweettest. There is no artist publishing tool outside tests. |
| D7 | Medium (security) | MoQ TLS private key is written by `rcgen` helper with default file mode (umask, typically 0644) in the caller-chosen cert dir. |
| D8 | Medium | Every bridge invocation attaches a *new* app interface and authorises new signing credentials on the conductor; repeated use from an app would accumulate interfaces. |
| D9 | Medium | S15 repair is host-preselected, single index; S16 seeking waits for sequential delivery (both documented). |
| D10 | Low | Only canonical 44-byte-header PCM16 WAV is playable; no FLAC. No `flac`/`ffmpeg`/libsndfile on the host. |
| D11 | Legal | No software licence chosen for this repository. Holochain conductor licensing must be reviewed before bundling its binaries. |

## 2. v1.0.0 release contract (proposed — awaiting user approval)

In scope, must be verified before tagging:

1. Installable Linux application (Ubuntu) with one launch command and a desktop entry.
2. Local graphical player (loopback browser UI driven by the Python player process; browser never receives keys, grants or PCM).
3. Holochain identity per installation (one agent shared by catalogue and storage cells), persistent conductor managed by the app.
4. Catalogue discovery: artists, albums, tracks, search.
5. Artist tools: profile, album, publish an encrypted WAV track, host it (S4 + MoQ), view requests, issue grants.
6. Noncommercial access workflow: listener requests access through Holochain; artist approves either a time-limited streaming grant or a perpetual personal-use licence; delivery through Holochain.
7. Streaming over certificate-pinned MoQ/QUIC with per-chunk SHA-256 + AES-GCM verification, play/pause/resume/stop/seek, bounded buffering and visible state.
8. Bounded recovery of missing ciphertext.
9. Download to an encrypted local library; offline playback of perpetual-licence tracks with no network services; explicit, user-initiated export of a playable WAV copy where the licence permits.
10. Key backup/restore (passphrase-encrypted).
11. Private-LAN (RFC1918) operation **only if** a real two-computer test passes; otherwise LAN is shipped as "experimental".

Explicitly **excluded** from v1.0.0 unless the user decides otherwise:
paid purchasing/payment providers, copyright-ownership verification,
public-internet hosting, NAT traversal, guaranteed availability or proof of
retrievability, DRM/revocation of exported copies, MP3/AAC.

## 3. Definition-of-done tracker

| Gate | Status | Evidence / blocker |
|---|---|---|
| Installs on a clean supported Ubuntu machine | MISSING | no package yet |
| Functional graphical music player | PARTIAL | S18 local UI (local JSON library only) |
| Holochain identities and catalogue discovery | MISSING | D3, D6 |
| Artist can publish an encrypted test track | MISSING (tests only) | D6 |
| Another authorised user can discover it | MISSING | D3 |
| Stream over authenticated MoQ/QUIC | PARTIAL | Sweettests only; D2 |
| Audio through physical speakers | BLOCKED | user confirmation |
| Pause, resume, stop, seek | PARTIAL | S11/S14/S16/S18 unit tests PASS |
| Missing encrypted chunks recovered | PARTIAL | S14 (S4 HTTP) / S15 (one preselected index); D9 |
| Network interruptions handled safely | PARTIAL | fail-closed; no reconnect |
| Download for permitted offline use | MISSING | D5 |
| Offline copy works without network services | MISSING | D5 |
| Private keys remain protected | PARTIAL | 0600 files in tests; no key store; D7 |
| Graceful user-error handling | PARTIAL | |
| Tests pass on the development environment | PASS (Python + Rust unit); Sweettests NOT RUN | see §1 |
| Two-computer networking validated | BLOCKED | hardware **and** D1 |
| Security limitations documented | PARTIAL | per-milestone docs |
| Fresh-machine installation test | NOT RUN | |
| Release documentation complete | MISSING | |
| Software licensing resolved | BLOCKED | user decision (D11) |
| Commerce scope implemented or excluded | BLOCKED | user decision; proposed: excluded |
| No unresolved critical/high security defects | NOT RUN | security review pending |
| User approval of v1.0.0 | BLOCKED | user |

## 4. Implementation log

See the end of this file; entries are appended as work lands.

### 2026-11-05 — audit

- Completed the audit above. Created branch `feat/v1-app-integration` (stacked on S18) in a separate worktree.
- First task selected: integrate the existing components into an application —
  persistent conductor, catalogue discovery, in-app grant workflow and a
  multi-session MoQ host — because every remaining product gate depends on it.

### 2026-11-05 — first integration slice (branch `feat/v1-app-integration`)

Done and verified:
- D1 fixed: storage DNA accepts literal RFC1918 MoQ endpoints (zome unit tests PASS).
- D3/D8: `music_app_bridge` (long-running, one app interface). **PASS** against a real `hc sandbox` conductor; a second, separate conductor process discovered Alice's published track through a local `kitsune2-bootstrap-srv` (same machine, not two computers).
- D2/D7/D9: `holochain-music-moq serve`/`fetch`/`fetch-document`: multi-file, multi-session, stable 0600 cert, subscriber-chosen start index / bounded object sets, signed manifest+receipt served over MoQ. 11 real-QUIC tests **PASS**.
- D4/D5: DNA entries for listener keys / access requests / grant records; perpetual personal-use licence schema (4 tests **PASS**).

Written but NOT yet tested (commit `wip`): `holochain_music/` application package — paths, binaries, key store + encrypted backup, conductor manager, bridge client, catalogue/trust resolution, download manager, player, artist/host service, app orchestrator, HTTP API. Still missing: CLI entry point, new UI, tests for all of these, three-conductor Sweettest of the new DNA, packaging, docs.
