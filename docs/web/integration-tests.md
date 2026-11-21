# Integration tests and evidence

## Test layers

| Layer | Command | What is real |
| --- | --- | --- |
| Crypto vectors (Node) | `node --test web/tests/v1-crypto.test.mjs` | vectors and verdicts produced by the native Python code |
| Crypto vectors (Chromium) | `node web/tests/chromium-crypto.mjs` | Chromium's own WebCrypto (BoringSSL) |
| Web units | `node --test web/tests/web-units.test.mjs` | WAV rules, config pinning, host URL policy, adapter retry/refusal |
| Adapter policy | `python -m unittest discover -s web/adapter` | real HTTP server; MoQ replaced by a fake |
| HWC build gate | `web/hwc/build-extension.sh` (full HWC core suite) | Imposter's security tests, malicious-gateway record tests with a genuine native record, call_remote authoriser vs Holochain 0.7 vectors |
| **Interop** | `python web/integration/run_interop.py` | everything, plus a test-only malicious gateway for M1: native Music artist and peer (unchanged `MusicApp`, own conductors, Lair, MoQ/QUIC host), Holochain 0.7.0 bootstrap/relay, accepted Imposter gateway in admission mode, media adapter, built web client with production CSP, real Chromium + HWC extension, two separate browser identities |

No mocks are used in the interop test. Since 2026-11-21 the grant reaches the
browser only through Holochain `call_remote` (checks E1–E5); the out-of-band
import is used only to feed grants that must be rejected (D4, I2, X1).

## Private grant delivery — local results, 2026-11-21

Environment: cloud Linux container (4 vCPU, no IPv6: `ipv4only` preload for
native processes), Holochain 0.7.0 release binaries (pins.json SHA-256),
sandbox Playwright with headed Chromium under Xvfb, Node 22.23.5, Python 3.13.
Commit under test: `027ee9878d749a33b37d96c091096192b659843b`. HWC built by
`web/hwc/build-extension.sh` (HWC core suite **622 passed**, 3 todo).
Gateway: call_remote candidate from `web/gateway/build-candidate.sh`
(SHA-256 `e703aaaf…6d2565`; accepted source tree reproduced, 207 Rust tests,
clippy `-D warnings`, fmt). Same DNA hashes and hApp SHA-256 as 2026-11-18.

**Run 5 (`--work /tmp/claude-0/interop5`, clean state): 29 PASS, 0 FAIL, 0 BLOCKED.
Checkpoint E: PASS. Checkpoint F: PASS.**

| Check | Result | Time |
| --- | --- | --- |
| A1 identity + origin authorised · A2 exact DNA hashes · A3 authenticated gateway, ready | PASS | 0.3 / 2.0 / 2.1 s |
| B1 discovery · B2 search · B3 artist page · C1 provenance | PASS | |
| C2 signed manifest + host receipt verified in-browser | PASS | 52.1 s |
| D0 no grant → no audio | PASS | |
| **E1** "Request licence" → `send_access_request` → Holochain `call_remote` → native artist returned Ok; UI `awaiting`, no decision claimed | **PASS** | 0.2 s |
| **E2** native `MusicApp.artist.requests()` lists the request with `listener_agent` = the browser agent (set from verified provenance), kind `perpetual-personal`, not granted | **PASS** | 2.0 s |
| **E3** before approval the browser shows no access; artist approves via `MusicApp.artist.grant()`; outcome `{"granted": true, "delivered": true}` (not queued) — `send_grant` → `call_remote` → gateway → HWC authorised `receive_grant` | **PASS** | 2.1 s |
| **E4** "Check for grants": `get_inbox_grants` returns exactly one private inbox row for the track; grant (`holochain-music/personal-licence/v1`) verified for this agent, recipient key and manifest; UI `granted` | **PASS** | 0.1 s |
| E5 second approval of the same request: two inbox rows, newest stored, older reported superseded, re-sync idempotent, one stored grant | PASS | 3.5 s |
| D2 decrypt and play to the end with the Holochain-delivered grant: 529 200 / 529 200 frames, 0 underruns, every chunk's plaintext SHA-256 equals the artist's canonical WAV | PASS | 12.7 s |
| D3 pause/resume/seek · D4 tampered grant rejected | PASS | |
| I1 track B: no access, not playable · I2 track A's grant rejected for track B | PASS | |
| R1 restart keeps identity, installation, grant · R2 track B still refused after restart · R3 track A re-verified and played to the end after restart (digests equal) | PASS | 6.1 / 1.0 / 13.1 s |
| G1 un-admitted held · G2 admitted · X1 listener B cannot use A's grant · X2 B cannot play | PASS | |
| G3 revocation drops the session · G4 restarting the revoked profile stays `admission-pending` | PASS | 3.0 / 20.9 s |
| M1 malicious gateway cannot forge catalogue records | PASS | 6.0 s |

Earlier runs on the way (kept as evidence of the failure modes):

| Run | Result | Cause → fix |
| --- | --- | --- |
| 1 | B3 FAIL (artist page not converged in 30 s) | B3 now retries like B1 |
| 2 | E1 BLOCKED `unsupported` | the record-verification wrapper (correctly) exposes only verified DHT members, hiding the new transport → transport registered separately |
| 3 | E1, E2 PASS; E3 FAIL: native artist got `ZomeCallResponse::Unauthorized` ("recipient refused the delivery") | browser grant reader expected the wrong serde shape; native `CapAccess`/`GrantedFunctions` are `{type, value}` tagged → fixed, `cap_grants` vectors added. The failure was fail-closed: nothing was stored, the artist did not report delivery |
| 4 | E1–E4 PASS (**E PASS**), E5 FAIL | test assumed a re-approval is byte-identical; it is a freshly wrapped grant → newest grant kept per track, test corrected |
| 5 | **29/29 PASS, E PASS, F PASS** | |

**Control run** (same commit, HWC build, **accepted** gateway `8f3f8e0b…`,
`HM_CONTROL_ACCEPTED_GATEWAY=1` so admission uses only `dht_read/dht_write/k2`):
A1–D0 PASS; **E1 FAIL as expected** — the gateway has no `/call_remote`, the
Music DNA's `remote()` reports the recipient unreachable, and the UI shows
"Access unavailable right now … nothing was delivered. Nothing has been
approved or declined". E and F: NOT MET. No delivery was reported falsely.

Checkpoint F definition (computed by `run_interop.py`): A1–A3, B1, C2, D0,
E1–E4 and D2 PASS in a **fresh** profile using only the UI's normal controls,
operator admission (`call_remote_send`, `call_remote_receive`) and the artist's
explicit approval; no grant file, key or browser-storage injection.

## Latest local results — 2026-11-18

Environment: cloud Linux container (4 vCPU, no IPv6 stack, so the
`ipv4only` preload shim was used for native processes), Holochain 0.7.0
release binaries, the sandbox's pre-installed Playwright 1.63.0 (interop:
headed Chrome for Testing 153.0.8010.12 under Xvfb; crypto vectors: headless
shell 157.0.8103.78), Node 22.23.5, Python 3.13 with `cryptography` 47. CI
pins Playwright 1.57.0 instead (Chromium 143.0.7499.4); results agree. Commit under test:
`cf34eade97bfb1127122cdff1372d17200731233` (harness, client and adapter;
later commits add docs/CI only).

Interop run (`--work /tmp/claude-0/interop-final`, clean state):
**19 PASS, 1 BLOCKED, 0 FAIL.**

| Check | Result | Time |
| --- | --- | --- |
| A1 browser identity created and origin authorised in HWC | PASS | 0.4 s |
| A2 Music hApp installed in HWC with the exact native DNA hashes | PASS | 2.0 s |
| A3 authenticated H2HC gateway session and network round trip (ready) | PASS | 2.1 s |
| B1 browser discovers the native artist track via Holochain (Browse) | PASS | 120.7 s (DHT arc growth) |
| B2 search finds the track by title | PASS | 0.1 s |
| B3 artist page lists the artist profile and track | PASS | 0.1 s |
| C1 track detail shows artist-authored record and DNA provenance | PASS | 0.1 s |
| C2 genuine signed manifest + host receipt fetched via adapter, verified in-browser | PASS | 1.3 s |
| D0 unauthorised playback refused (no grant, no audio) | PASS | 0.1 s |
| E1 private access request over Holochain from the browser | **BLOCKED** | `[HostFn:call] No ConductorCell in target` — see [grants.md](grants.md) |
| D1 artist issues a real v1 licence to this browser (out-of-band, operator-assisted) | PASS | 3.1 s |
| D2 browser verifies, decrypts and plays the genuine audio to the end | PASS | 12.7 s for a 12 s track; 529 200/529 200 frames; 0 underruns; every chunk's plaintext SHA-256 equals the artist's canonical WAV |
| D3 pause, resume and seek during playback | PASS | 4.5 s |
| D4 tampered grant rejected | PASS | 0.1 s |
| R1 browser restart keeps identity, installation and grant | PASS | 6.1 s |
| G1 un-admitted identity held at admission-pending | PASS | 22.1 s |
| G2 second identity ready after admission | PASS | 2.1 s |
| X1 listener B cannot use listener A's grant | PASS | `grant not valid for this listener/owner/file` |
| X2 listener B cannot play the encrypted track | PASS | 0.0 s |
| G3 revoked identity loses the authenticated gateway session | PASS | 3.0 s |

Run identifiers: native DNAs `uhC0k6tJ5iJFWusUqhJjjt0crDBsW7AhwRqzXhDeMf6reThaN7Uqn` /
`uhC0kkLUOg2uytGWLz_sTeVtfJBqa0criBmAYAPwAIUhoDp_9G4RV`, hApp SHA-256
`6336c245bac1d769f0e6081a01e0e16e03a13c679b6f971839464f6afffd8d54`, gateway
SHA-256 `8f3f8e0b…f138746f`. Agents and manifest digests are per run.

Other local results at the same commit: crypto vectors Node 12/12 tests,
Chromium 23/23 grant verdicts equal to Python plus exact chunk decryption,
web units 6/6, adapter policy 5/5, desktop suite `python -m unittest discover
-s tests` 447 tests OK (36 opt-in skips).

## CI (GitHub Actions)

Workflow `.github/workflows/web-browser-player.yml`, pull requests only (one
run per ref). Browser jobs run on `ubuntu-24.04`: Playwright 1.57.0 cannot
install Chromium on `ubuntu-latest` (26.04) — that was an infrastructure
failure, not a test failure; the Chromium crypto vectors are unchanged.

| Commit | Run | web-units | chromium-crypto | adapter | interop |
| --- | --- | --- | --- | --- | --- |
| `350a84a` | [44423964864](https://github.com/ConorTttttt/holochain-music/actions/runs/44423964864) | PASS | FAIL (infrastructure: Playwright on 26.04) | PASS | FAIL (bug: HWC build branch name refused by Imposter's apply.py) |
| `cebbef0` | [44426377461](https://github.com/ConorTttttt/holochain-music/actions/runs/44426377461) | PASS | PASS | PASS | PASS — 19 PASS, 1 BLOCKED (E1), 0 FAIL |
| `bd28f04` | [44431476547](https://github.com/ConorTttttt/holochain-music/actions/runs/44431476547) | PASS | PASS — 23/23 grant verdicts equal Python, exact chunk decryption | PASS | PASS — 20 PASS, 1 BLOCKED (E1), 0 FAIL, including M1 (malicious gateway) and the HWC patch build gate |

Later commits on the PR record their own runs in the PR description.

## Record verification and malicious gateway (local, 2026-11-19)

Same environment as above, with the HWC build from `web/hwc/build-extension.sh`
(Imposter patches + routing + record verification + inert call_remote
authoriser; HWC core suite 601 passed, 3 todo).

| Run | HWC build | Result |
| --- | --- | --- |
| verified | with record verification | **20 PASS, 1 BLOCKED (E1), 0 FAIL** — includes M1: the tampering gateway forged 3 track records, the UI never showed them |
| control | previous build without record verification | **M1 FAIL**: the forged title "FORGED! Interop Tone" reached the UI (all other checks as before) |

The first verified attempt failed B1: genuine native records were rejected.
Captured gateway responses showed HWC's wire-action normaliser kept
`entry_type.App` in the gateway's alphabetical key order; Holochain hashes and
signs Rust's `AppEntryDef` order. Fixed in the patch, with the captured native
record kept as a regression fixture.

Limit seen in M1: a rejected record looks like "not visible yet" in the UI
(denial of service is not distinguishable from slow synchronisation).

## Not covered yet

* Two physical machines, public internet, TLS on gateway/adapter (localhost
  only here).
* Firefox / Android HWC.
* Host outage mid-stream against the adapter (the reused desktop `Download`
  worker has its own native tests; the browser retry path is unit-tested).
* Firefox Desktop live run of the grant workflow (Firefox/Geckodriver not available in this container; extension builds and the executor tests pass).
* Imposter mixed-browser and repeatable-lobby acceptance against the candidate gateway (NOT RUN).
