# Holochain Music v1.0.0-rc1 — release-blocker report

**This is a release candidate, not a production release. Do not tag v1.0.0.**

Every **PASS** names something actually executed on the development host
(HP Pro Mini 400 G9, Ubuntu 26.04.1 LTS, Holochain 0.7.0, Python 3.14.4).
Legend: **PASS** executed and passed · **FAIL** executed and failed ·
**BLOCKED** needs hardware, a person or a decision · **NOT RUN** not executed.

Branch `feat/v1-app-integration` (worktree `/mnt/holochain/holochain-music-v1`),
stacked on S18 (`0ac4687`). Nothing pushed, merged or tagged. Package
checksums are recorded outside the package (§6).

## 1. Decisions

| Decision | Status |
|---|---|
| Private peer-to-peer grant workflow | Provisionally accepted for RC testing. **Final approval pending**: see `docs/private-grant-security-review.md`. |
| No real payments in v1.0.0 | Accepted. Free artist-issued 24 h streaming grants and perpetual personal licences only. |
| Apache-2.0 for original code | Under investigation: `docs/licensing-audit.md`. **Not applied.** |
| CAL-1.0 obligations (bundled `holochain`; `hdk`/`hdi` compiled into our DNAs) | **BLOCKED – legal review.** The `.deb` must not be distributed publicly until resolved. |
| Rust/Nix build cache | Preserved. Cleanup options in §7. |
| Push / merge / tag | Not done; awaiting permission. |

## 2. Release blockers (must clear before v1.0.0)

| # | Blocker | Owner action |
|---|---|---|
| B1 | Physical speaker playback not yet heard by a person | Test 1, `docs/hardware-test-plan.md` |
| B2 | Two-physical-computer LAN test not run | Test 2 (LAN stays **experimental** until it passes) |
| B3 | Physically disconnected offline playback not run | Test 3 |
| B4 | Clean-machine `apt install` not run | Test 4 |
| B5 | Repository licence not chosen; CAL-1.0 obligations unresolved; package lacks licence texts and a source offer | Decision + legal review |
| B6 | Private-grant trust model not formally approved | Review `docs/private-grant-security-review.md` |
| B7 | CI workflow `.github/workflows/v1-app.yml` never run | Needs permission to push |
| B8 | No independent security review | External reviewer |
| B9 | Stacked draft PRs #5–#22 and this branch unmerged | Merge plan + permission |
| B10 | Acoustic seek latency not yet measured by ear/recording on the HP | Test 1b |

## 3. Evidence this session (2026-11-06)

| Test | Result |
|---|---|
| Python suite, all non-opt-in tests (real S4 + MoQ binaries) | **PASS 283** after the seek fix (7 skipped = the two opt-in e2e suites below), 111 s |
| Seek performance regression tests (5-minute WAV), 7 tests | **PASS**. 15 seeks: median 0.8 ms, p95 1.1 ms to first PCM (null output); whole file verified once per open; tamper-after-open caught; coalescing; monotonic status |
| Two-conductor end-to-end flow (publish → discover → refused without grant → private request → private licence → stream + mid-download seek → download → no-network playback + export) | **PASS**, 145 s |
| Three-agent grant security (artist, listener, attacker Mallory), 6 tests | **PASS**, 146 s. Malformed requests refused and not stored; provenance cannot be spoofed; forwarded genuine licence and forged grant import 0 and cannot play; duplicate delivery harmless; 21st message from one sender rate-limited and not mistaken for "offline"; request queued while the artist was fully offline delivered 20 s after restart |
| Existing three-conductor Sweettests (prebuilt) against the current DNAs | catalogue+storage identity (2), S9, S16: **PASS**. Earlier today with the previous DNA revision: all 11 binaries / 13 tests PASS |
| Rust: moq-music 8, storage integrity 3, catalogue integrity 6 | **PASS** |
| UI script syntax (`node --check`) | **PASS** |
| `.deb` reproducibility (two assemblies, same inputs) | **PASS**, identical SHA-256 |
| Installed-package black-box smoke test (extracted `.deb`, system Python, clean env) | **PASS** (see §6 for the final run) |
| Admin-WebSocket Origin check (hostile Origin → 400; bridge → 101) | **PASS** (in e2e) |

## 4. Catalogue discovery delay — investigated and mitigated

Symptom: first discovery between fresh peers sometimes took minutes (283 s,
then 159–421 s).

1. **Bootstrap back-off** (kitsune2 doubles its poll interval to a 5-minute cap
   and never resets it). Capped at 30 s. Measured: this alone **did not** remove
   the worst case (capped trials included 267 s and 421 s).
2. **Root cause** (from conductor logs of a slow run plus kitsune2 0.5.0 /
   holochain_p2p 0.7.0 source): a transient QUIC failure at start-up
   (`MultipathNotNegotiated`, failed pings, handshake aborts) marks the peer
   *unresponsive*. The mark is cleared only when that peer publishes **newer**
   agent info, which by default happens only in the last 5 minutes of a
   20-minute agent-info life.
3. **Fix**: re-sign agent info every ~15–30 s (`coreSpace.reSignFreqMs=15000`,
   `reSignExpireTimeMs=1170000`). Cost: one small agent-info update every
   ~30 s per peer, acceptable at LAN scale.

| Configuration | Trials | Discovery seconds | Over 60 s |
|---|---|---|---|
| kitsune2 defaults | 5 | 159, 3, 421, 0, 25 | 2 |
| bootstrap cap only | 9 | 37, 0, 27, 267\*, 421\*, 9.5, 1, 10.2, 0 | 2 |
| cap + frequent re-sign (shipped) | 8 | 27.9, 1.0, 0.0, 28.3, 21.4, 21.2, 35.4, 22.2 | **0** |

\* overlapped with another test on the same machine.

In 3 of the 8 shipped-config trials the start-up flap occurred, and the
unresponsive mark was pruned about 8 s later.

**Later observations with the shipped configuration** (not part of the
controlled measurement): installed-package smoke tests 17 s and 71 s;
end-to-end tests 46 s and **270 s**. The e2e figure includes waiting for the
artist profile as well as the track, and no network logs were captured. Long
delays are therefore **reduced but not eliminated**, and this remains an open
risk (§8). Same machine, loopback relay:
LAN behaviour must be confirmed in Test 2, with the diagnostic logging
described in the hardware test plan.

## 4a. Seek performance — measured before and after (video report, 2026-11-06)

Method: `packaging/bench-seek.py` plays a 5:31, 44.1 kHz stereo licensed
offline track through the real app path (`MusicApp` → `Player` → S11 player →
`aplay -D null`). It makes 20 seeded seeks while playing and measures the
time from the seek call to the first PCM block for the new position written
into the output process. It samples the reported position every 50 ms.

| | Before (`f5cc661`) | After (`852d0b7`) |
|---|---|---|
| Seek → first PCM written, median | **3250 ms** | **2.3 ms** |
| p95 | 3837 ms | 2.7 ms |
| max | 3845 ms | 2.7 ms |
| First play of the track (open + verify) | 654 ms | 96–149 ms |
| Reported position moved backwards while "playing" | 18 times | 0 |
| Longest frozen position while "playing" | 2.96 s | 0 s |

The "after" figure was measured twice, with the player's own metrics and
with the baseline's independent write-timing method; both gave median 2.3 ms.

Causes (from instrumenting the path):

1. `AlsaOutput.abort` sent SIGTERM and waited up to 3 s; `aplay` does not exit
   promptly, so each seek blocked about **3.0 s**. It is now killed at once
   (aborted audio is discarded, not drained).
2. Each seek re-resolved and re-opened the track: full-file SHA-256 twice plus
   a decrypt of the whole file (about 270 ms). The track is now verified once
   per open. Seeks reuse the opened reader, and each chunk played is still
   SHA-256- and AES-GCM-checked before output.
3. During that stop the state stayed "playing" while the position fell back to
   the previous segment start (the backward jumps and frozen timeline).
4. The UI applied poll responses in arrival order, so a poll in flight during a
   seek could repaint the old position. Statuses now carry `seq`; older ones
   are dropped and the seek target is shown until confirmed.

Each seek still restarts the ALSA output. That is deliberate: it is the only
way to discard audio already queued in `aplay` without a native ALSA binding.
The restart now costs about 2 ms.

**Not measured here: acoustic latency.** The figures above stop at the ALSA
write. With the 200 ms device buffer and a 250 ms start burst, expect
playback to start within the device's own period latency after the first
write. In the UI, seek requests are deliberately coalesced for 120 ms.
Measure on the HP with Test 1b.

## 5. Defects found and fixed this session

| ID | Severity | Fix |
|---|---|---|
| D17 | High | Private inbox lifetime cap (2000) allowed permanent denial of service by a few throwaway agents. Replaced with 20/sender/day and 500/all/hour. |
| D18 | Medium | Private request entry hashes were guessable by another artist who knew the listener's X25519 key. Recipient now adds a random nonce. |
| D19 | High | Remote refusals arrive as `NetworkError`; they were reported as "offline" and would have been retried for 7 days. Now tagged and classified. |
| D20 | High | Bridge processed calls serially: one call to an offline peer (~60 s) froze all conductor calls. Bridge and client are now concurrent. |
| D21 | High (usability) | Discovery delays up to 7 min (§4). |
| D22 | Medium | Requests needed the artist's host online, so the outbox could never help. Requests now use only the DHT track record. |
| D23 | Low | Host-outage test silently skipped with the faster release binary. Now rate-limited and asserting. |
| D24 | Low | Bridge reader thread raced `stop()`. |
| D25 | High | Each seek/track change blocked about 3 s on `aplay` SIGTERM (§4a). |
| D26 | Medium | Each seek re-verified and fully decrypted the whole file (§4a). |
| D27 | Medium | Position moved backwards and froze during seeks; status said "playing" before audio resumed (§4a). |
| D28 | Medium | UI applied stale poll responses over newer seek state (§4a). |

Earlier fixes D1–D16: see git history and `CHANGELOG.md`.

## 6. Release-candidate artefacts

Assemblies from the same inputs are byte-identical. Rebuilding the Rust
binaries from source reproducibly has **NOT** been verified. The final package
SHA-256, per-file checksums and the final smoke-test result are recorded in
`docs/rc1-checksums.md`, which is written after the build and is not inside
the package.

Bundled binaries: `holochain` 0.7.0, `hc` 0.7.0, `kitsune2-bootstrap-srv`
0.5.1 (from the local cargo install), `holochain-music-moq` (release build),
`music_app_bridge` (debug build, stripped).

## 7. Disk (6.8 GB free at last check; nothing deleted)

Safe, regenerable cleanup candidates, smallest risk first:

1. `holochain-music-v1/crates/moq-music/target/debug`: 1.5 GB (superseded by
   the release build).
2. Older duplicate Sweettest binary
   `music-e2e/target/debug/deps/catalogue_storage_identity_sweettest-67ec04025729654b*`:
   0.8 GB.
3. `holochain-music-v1/{dna,music-dna}/target/debug`: 1.4 GB (rebuilds in
   about a minute).
4. Leftover test sandboxes in `/mnt/holochain/tmp/hmv1`: 0.2 GB (after
   stopping their two conductors and the bootstrap server from the previous
   session).

Keep the main `music-e2e/target` cache (17 GB). The Sweettests run from it.

## 8. Known limitations (shipping with the RC)

- Catalogue discovery between fresh peers usually takes seconds but has been
  observed at up to about 4.5 minutes after the mitigation (§4).
- Private grants need a moment when both apps are online (the outbox retries
  for 7 days while the app runs). Request and grant volume and timing per
  agent is public metadata. The relay sees which peers talk.
- No key rotation (artist, host or listener). No OS keyring; the lair
  passphrase is a local 0600 file.
- WAV/PCM16 input only. Same-machine networking is verified; LAN is
  experimental; no public-internet hosting.
- Holochain binaries built for Ubuntu 26.04 only.
- Sweettests were run from prebuilt S16-era test binaries. The music-e2e
  test crate was not recompiled because of disk space.
