# Holochain Music v1.0.0 — release readiness

Living document. Every **PASS** names a command that was actually run on the
development host (HP Pro Mini 400 G9, Ubuntu 26.04.1 LTS, Holochain 0.7.0,
Python 3.14.4). Legend: **PASS** executed and passed · **FAIL** executed and
failed · **SKIP** skipped · **BLOCKED** needs hardware, credentials or a
decision · **NOT RUN** not yet executed.

Branch `feat/v1-app-integration` (worktree `/mnt/holochain/holochain-music-v1`),
stacked on S18 (`0ac4687`). Not pushed, merged or tagged.

## 1. Decisions recorded

| Decision | Status |
|---|---|
| Public listener→track grant records rejected as default | Implemented: private remote-call inbox (security-model §3). **Trust-model change awaiting owner approval.** |
| v1.0.0 has no real payments | Accepted. Free artist-issued streaming grants and perpetual personal licences only. The grant `kind` field and request/approve flow are the extension points for future commerce. |
| Software licence for this repository | **BLOCKED – owner decision** |
| Redistribution terms of the bundled Holochain binaries | **BLOCKED – owner/legal review** |

## 2. Release contract (v1.0.0, payments excluded)

| Gate | Status | Evidence |
|---|---|---|
| Installs on a clean supported Ubuntu machine | PARTIAL | `.deb` extracted to a separate prefix and run with system Python, clean env, no dev paths: **PASS** (`packaging/smoke-test.py`, 68 s). `apt install` on a separate clean machine: **NOT RUN (needs your hardware)** |
| Functional graphical player | PASS | Real launcher + live conductor rendered in headless Chrome; artist publish through the UI API shown in the catalogue |
| Holochain identity + catalogue discovery | PASS | e2e: two conductors, bootstrap + relay on loopback |
| Artist publishes an encrypted track | PASS | e2e, smoke test, UI smoke |
| Another authorised user discovers it | PASS | e2e (same machine, separate conductor processes) |
| Stream over authenticated MoQ/QUIC | PASS | e2e: 21-chunk track at 256 KiB/s host rate |
| Audio through physical speakers | **BLOCKED** | ALSA path unchanged from S11; v1 app with `--audio alsa` not yet heard by a person |
| Pause / resume / stop / seek | PASS | player unit tests; e2e seek mid-download (transfer restarted at the needed chunk, exact PCM) |
| Missing encrypted chunks recovered | PASS | real-QUIC: listener-driven object sets, seek-start + backfill, corrupt object refused |
| Network interruptions handled safely | PASS (local) | host outage then resume keeps verified chunks; 6 failures → explicit `unavailable` |
| Download for permitted offline use | PASS | e2e, smoke test |
| Offline copy works without network services | PASS (software) | e2e: all services stopped, fresh process with sockets and subprocesses disabled plays exact PCM and exports an identical WAV; smoke test `--offline`. Physically disconnected machine: **NOT RUN** (procedure in installation.md) |
| Private keys protected | PARTIAL | 0600/0700, O_NOFOLLOW, refuse group-readable or symlinked keys, encrypted backups. No OS keyring (documented) |
| Graceful user errors | PASS (tested set) | API tests: bad input, offline, missing grant, bad WAV, export rules |
| Tests pass on the development environment | PASS | §3 |
| Two-computer networking | **BLOCKED (hardware)** | DNA defect D1 fixed; procedure in installation.md. LAN shipped as **experimental** |
| Security limitations documented | PASS | docs/security-model.md |
| Fresh-machine installation test | **BLOCKED (hardware)** | see first row |
| Release documentation complete | PASS (RC) | README, user guide, installation/LAN/tests, security model, changelog |
| Software licensing resolved | **BLOCKED** | owner |
| Commerce scope excluded | PASS (decision) | |
| No unresolved critical/high security defects | PARTIAL | D12 found and fixed; independent review not done (security-model §7) |
| Owner approval | **BLOCKED** | |

## 3. Test results (this session, 2026-11-06)

| Suite | Result |
|---|---|
| Python, all (`python -m unittest discover -s tests`, real S4 + MoQ binaries) | **PASS 260**, SKIP 1 (opt-in e2e), 103 s |
| ↳ new v1: storage/keys/backup/library/WAV (13), player (7), real-QUIC streaming (5), MoQ host (11), licence (4), API (9 incl. backup restore) | PASS |
| v1 end-to-end two-conductor flow (`HOLOCHAIN_MUSIC_E2E=1`) | **PASS ×4** (latest includes the admin-Origin regression check) |
| Installed-package black-box smoke test (final package `75849927…3abb2`, after the admin-Origin fix) | **PASS** (83 s) |
| `.deb` assembly reproducibility (two builds, same inputs) | **PASS** identical SHA-256 `079c6ca5…7df3`. Rebuilding the Rust binaries reproducibly: NOT RUN |
| Rust: moq-music 8 · storage integrity 3 · catalogue integrity 6 | PASS |
| Existing three-conductor Sweettests (prebuilt S16-era binaries) **against the new v1 DNAs** | catalogue 2, catalogue+storage identity 2, S7, S9, S10, S11, S12, S13, S14, S15, S16: **all PASS** (11 binaries, 13 tests) |

E2E timings (same machine): both instances online 10–33 s; publish 0.2–3.7 s;
**first catalogue discovery 0–283 s** (high variance in initial gossip); private
request → grant 0.5–0.6 s; first streamed audio 0.8 s; seek rebuffer about 1.1 s
total. These are not performance benchmarks.

## 4. Defects found and fixed this session

| ID | Severity | Fix |
|---|---|---|
| D12 | **High** | Conductor admin WebSocket accepted any browser Origin (verified with `Origin: http://evil.example` → 101). Now restricted to the bridge Origin (→ 400). |
| D13 | High | Zome lockfiles resolved Holochain type crates 0.7.1, whose `CapGrant` wire format the 0.7.0 conductor rejects (`init` failed). Pinned to 0.7.0. |
| D14 | Medium | Downloads retried a stale host URL forever after a host moved; waiters silently restarted `unavailable` downloads. Fixed: explicit retry re-resolves hosts. |
| D15 | Medium | A missing artist profile was cached for 60 s, so new tracks showed "Unknown artist". |
| D16 | Low | Non-reproducible `.deb` (Installed-Size from `du`, umask 002 permissions). |
| D1–D5, D7, D8 | — | Fixed in earlier commits (LAN endpoints, multi-session host, catalogue browse, grant workflow, perpetual licence, cert 0600, single bridge interface). |

## 5. Open risks and remaining work

1. **Owner approval** of the private-inbox trust model (security-model §3).
2. **Hardware**: speaker playback, two-computer LAN, clean-machine `apt install`,
   physically disconnected offline playback.
3. **Licensing**: repository licence; Holochain binary redistribution terms.
4. Discovery latency on fresh peers can be minutes; the UI says so, but it is
   a usability risk.
5. Both peers must be online for request/grant delivery (no store-and-forward).
6. No OS keyring; the lair passphrase is a local file.
7. The stacked draft PRs #5–#22 are unmerged; this branch needs a PR and CI
   updates (`.github/workflows/v1-app.yml` added but never run — it runs on push).
8. Sweettests were run from prebuilt S16-era binaries; the music-e2e test crate
   was not recompiled, because that rebuild would not fit on disk. No new
   Sweettest covers the private inbox; it is covered by the real two-conductor
   e2e test instead.
9. WAV/PCM16 only; no FLAC (no decoder available on the host without new
   dependencies).
10. Disk: `/mnt/holochain` has about 7 GB free. The largest reclaimable item is
    the 16 GB `music-e2e/target` build cache in the main checkout. Pruning it
    needs owner approval.
11. Holochain binaries are bundled as built on this machine (Ubuntu 26.04 only).

## 6. Implementation log

- 2026-11-05 — audit; LAN-capable DNA, app bridge, multi-session MoQ host
  (`09c4b45`); licence + documents over MoQ (`ab67d89`); untested app package
  (`3826d11`).
- 2026-11-06 — app tests + retry fixes (`2f89907`); private inbox, CLI, real
  e2e (`a0ee4e3`); UI + API tests (`0b80983`); packaging (`7d34803`); admin Origin
  fix (`f8f97a1`); docs (`6234fb1`).
