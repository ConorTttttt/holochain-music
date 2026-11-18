# Integration tests and evidence

## Test layers

| Layer | Command | What is real |
| --- | --- | --- |
| Crypto vectors (Node) | `node --test web/tests/v1-crypto.test.mjs` | vectors and verdicts produced by the native Python code |
| Crypto vectors (Chromium) | `node web/tests/chromium-crypto.mjs` | Chromium's own WebCrypto (BoringSSL) |
| Web units | `node --test web/tests/web-units.test.mjs` | WAV rules, config pinning, host URL policy, adapter retry/refusal |
| Adapter policy | `python -m unittest discover -s web/adapter` | real HTTP server; MoQ replaced by a fake |
| **Interop** | `python web/integration/run_interop.py` | everything: native Music artist and peer (unchanged `MusicApp`, own conductors, Lair, MoQ/QUIC host), Holochain 0.7.0 bootstrap/relay, accepted Imposter gateway in admission mode, media adapter, built web client with production CSP, real Chromium + HWC extension, two separate browser identities |

No mocks are used in the interop test. The out-of-band grant step (D1) is
labelled as such.

## Latest local results — 2026-11-18

Environment: cloud Linux container (4 vCPU, no IPv6 stack, so the
`ipv4only` preload shim was used for native processes), Holochain 0.7.0
release binaries, Chromium 157 (Playwright 1.57.0) under Xvfb, Node 22.23.5,
Python 3.13 with `cryptography` 47. Commit under test:
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

## CI

`.github/workflows/web-browser-player.yml` runs the same layers in separate
jobs (`web-units`, `chromium-crypto`, `adapter`, `interop`) and writes a
PASS/FAIL/BLOCKED table to the job summary with the sanitized evidence as an
artifact. Results for this branch are reported in the pull request, not here,
so this file does not claim a CI result it has not seen.

## Not covered yet

* Two physical machines, public internet, TLS on gateway/adapter (localhost
  only here).
* Firefox / Android HWC.
* Host outage mid-stream against the adapter (the reused desktop `Download`
  worker has its own native tests; the browser retry path is unit-tested).
* Private grant delivery (blocked).
