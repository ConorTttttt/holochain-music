# Post-RC1 signed MoQ artwork — real two-device acceptance runbook

**Owner:** Agent 9 / post-RC1 artwork implementer · **status:** READY FOR EXECUTION, **NOT RUN** · **written:** 2026-11-17

**Baseline evidence:** `main` `bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637`; historical implementation PR [#38](https://github.com/ConorTttttt/holochain-music/pull/38), head `f7311d6eecbceca19e6f3eefaea54cdabf70f245`. The old branch fails its CI and is divergent. Run this **only on a minimal current-main-based artwork integration PR after its automated checks pass**; the old branch is not an acceptable final test target.

## Scope / safety preconditions

The acceptance must show **artist-authored, signed, public artwork from a newly published album**, delivered from Alice's **authenticated and pinned MoQ/QUIC host**, with verified ciphertext/chunk hashes and an offline cache which still rejects tampering. It must **not** require an audio content grant or disclose/mutate audio keys.

- Use **two physically separate computers** (Alice artist/host, Bob listener), **distinct Holochain agent identities**, **separate disposable data directories/profiles**, and known compatible hApp/DNA and MoQ versions. Record OS, package, branch/commit SHA, DNA hash, Holochain version, MoQ binary version and whether LAN is explicitly enabled. Do not reuse production identities, keys or caches.
- Both devices must already demonstrate authenticated catalogue discovery, pinned endpoint retrieval and normal audio/grant controls on the same network. Do not count two tabs or two profiles on a single computer as the required physical test.
- Only Alice serves a **new** album whose immutable v1 record contains `artwork_manifest_sha256` for the full signed S1 artwork manifest. Do not republish an older `artwork_manifest_sha256: null` album under the same ID: versioned album updates are explicitly out of scope.
- Use a test PNG that passes the existing scrubbed, bounded importer (8-bit RGB/RGBA PNG, max 1200 × 1200, max 768 KiB). Use a second ungranted music track or no music licence on Bob to prove artwork and audio authorization remain independent.
- All negative-case corruption must target **copies in disposable test profiles**. Never mutate production CAS, release identity or receipt data; do not circulate private signing keys, access grants, bearer tokens, local TLS private keys or user library content as test evidence.

## Automated preflight (record precise stdout/stderr and return codes)

From the proposed **current-main-based** artwork integration checkout, not from PR #38's old head:

```sh
git rev-parse HEAD
git status --short
python3 -m compileall -q holochain_music music_catalogue holochain_storage
python3 -m unittest discover -s tests -p 'test_album_artwork.py' -v
python3 -m unittest discover -s tests -p 'test_artwork_transport.py' -v
python3 -m unittest discover -s tests -p 'test_artwork_catalogue.py' -v
python3 -m unittest discover -s tests -p 'test_ui_player_polish.py' -v
python3 -m unittest discover -s tests -p 'test_ui_offline_library.py' -v
python3 -m unittest discover -s tests -p 'test_ui_library_collections.py' -v
node --check holochain_music/ui/app.js
```

Also require the PR's relevant Python/Rust/MoQ/storage/conductor/Windows CI checks to **conclude**; do not conflate queued, cancelled and skipped jobs with passes. Record the real-conductor tests separately from mocked unit tests. Check no changed DNA, music license/grant protocol, player audio endpoints, certificate trust assumptions or pre-existing local-artwork import regression.

## Positive acceptance scenarios

| Case | Procedure | Required observation / evidence |
|---|---|---|
| A1 — trusted publication | On Alice, create a **new** album with canonical test PNG and publish a linked test track; inspect the album metadata and host evidence via the app's trusted code path | Artist is authenticated as the album author; `artwork_manifest_sha256` pins the complete artist-signed S1 manifest (not raw PNG); S2 owner key binding and S2 file/host commitments are traceable; CAS chunks and receipt exist |
| A2 — first peer retrieval | On a **clean Bob profile**, with no artwork cache and **no Alice audio grant**, discover Alice in Browse/Artist page while both devices are online and host reachable | Vinyl placeholder becomes the correct cover via the authenticated loopback endpoint; host MoQ is pinned, artist and album provenance checked; no externally sourced image URL or audio key/grant is present in browser state or logs |
| A3 — offline verified cache | Wait until the image is fully verified and persisted on Bob, shut down network access, restart Bob **fully offline**, and open the offline library/player reference for Alice's cover | Identical clean PNG appears without MoQ or online conductor; cache read independently verifies signed manifest + ciphertext evidence and avoids trusting raw PNG solely because it exists on disk |
| A4 — playback isolation | With Bob legitimately granted access to a **different** test audio track, play/scrub/pause while artwork is loading/failing/retrying | One playback session and normal seek/grant behaviour continue; artwork latency never blocks audio, and licence expiry/entitlement remains unchanged |
| A5 — accessibility / themes | With and without cover, test Browse/Library/Artist page and player at narrow viewport and 200% zoom, light/dark/Amethyst, keyboard-only navigation and reduced motion | Image has appropriate decorative/meaningful semantics as implemented; fallback visible, no hidden interactive focus; no remote token-bearing URLs or theme regressions |

For A2, record **time from authenticated album discovery to verified image display**, including the first HTTP 202 response and subsequent successful response if present. A permanent 202 spinner, repeated fetches or an incorrect identity binding is a failure, not a pass.

## Rejection and resilience matrix (all cases mandatory)

| Case | Isolated manipulation / environmental condition | Required result |
|---|---|---|
| N1 | On a disposable Bob/Alice fixture, corrupt one downloaded ciphertext chunk or signed-manifest hash | SHA-256/AES-GCM/manifest validation rejects image; no unverified display or acceptance into cache |
| N2 | Swap the album ID with a different album or artist agent while keeping payload/manifest | The public artwork file ID/key derivation and Holochain album/artist binding reject substitution |
| N3 | Supply a forged signer or mismatched S2 owner-key binding/author record in isolated tests | Authenticated artist-key and author checks reject the response |
| N4 | Supply an invalid host receipt, stale/wrong file commitment or wrong replica claim | Host/receipt/commitment chain rejected before image display |
| N5 | Point to MoQ service with incorrect TLS fingerprint or unauthorised LAN address | Pinned connection rejected; no arbitrary HTTP fallback or implicit LAN enablement |
| N6 | Make Alice's host unreachable midway through Bob's first request, then restore it | Vinyl fallback; bounded concurrency/retry/cooldown; recovery on the same app after connectivity is restored without restarting audio |
| N7 | Start Bob offline with **no verified cache** for a new Alice album | Vinyl fallback, not an invented or untrusted image; no endless 202 loop |
| N8 | After A3 succeeds, tamper Bob's saved PNG, manifest metadata, or CAS ciphertext **in a disposable copy**, then restart offline | Cache read rejects altered contents and falls back to vinyl; cannot bypass validation by retaining a raw-image file |
| N9 | Open two or more missing covers concurrently; browse away or restart during a fetch | Fetch worker limit (two), no stuck busy state or unbounded jobs; no breakage of player or UI event loop |
| N10 | Attempt an older v1 album with `artwork_manifest_sha256: null` | Remote artwork is not falsely asserted; existing local artwork and vinyl fallback retained; no ID rewrite/migration |

Synthetic tampering/unit tests can supplement but do **not** replace the physical positive Alice/Bob A1–A4 cases. Negative cases that cannot be safely staged in hardware must be labelled separately as **automated simulation only**, not “physical pass”. Use signed-fixture construction rather than changing real DHT/installed DNA to simulate author failures.

## Evidence capture template

Copy this section into the implementing PR or a linked test report, fill **each case**, and attach sanitized logs/screenshots. Do not mark an unexecuted case as PASS.

```text
Run date/time and UTC offset:
Tester(s):
Artwork integration PR, commit SHA and diff URL:
Alice device: OS/version, profile label (non-secret), Holochain/MoQ versions, DNA hashes:
Bob device:   OS/version, profile label (non-secret), Holochain/MoQ versions, DNA hashes:
Network: topology, explicit allow_lan value, discovery delay, link-loss method:
Automated preflight: command, return code, passes / failures / skipped:
CI job URLs, conclusion (success / failure / cancelled / queued):
A1: PASS / FAIL / BLOCKED / NOT RUN — evidence:
A2: PASS / FAIL / BLOCKED / NOT RUN — evidence:
A3: PASS / FAIL / BLOCKED / NOT RUN — evidence:
A4: PASS / FAIL / BLOCKED / NOT RUN — evidence:
A5: PASS / FAIL / BLOCKED / NOT RUN — evidence:
N1 ... N10: per-case PASS / FAIL / BLOCKED / NOT RUN and physical/synthetic designation:
Artwork discovery-to-display latency and repeated HTTP 202 behaviour:
Negative auth, certificate, cache-tamper logs (redacted):
Unchanged audio/grant proof:
Residual issues / reproducible defects:
Retest required / owner:
Final recommendation: GO / NO-GO (reviewer and date):
```

## Merge gate and residual risk

**NO-GO** for the post-RC1 artwork feature until the current-baseline implementation and all mandatory acceptance cases are evidenced. The old PR's reported 74 focused test passes were on `f7311d6`, are not current-baseline tests, and the old PR's GitHub Actions workflows failed. There is **no executed physical Alice/Bob artwork evidence** in this Agent 9 audit.

Even after the above passes, separately track global cache eviction, versioned cover replacement on old albums, source-image conversion, host failure tolerance and Windows binary packaging. None justifies a silent DNA migration or changes to signed music/grants.
