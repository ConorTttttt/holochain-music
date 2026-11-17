# Agent 6 — independent access-grant/v2 security review (17 November 2026)

**Decision: RED / DO NOT MERGE.** Music #52 and Media Core #14 remain draft; v2 is an opt-in P1 feature, not a Music RC1 prerequisite. This is a static-source review plus one **independent primitive-level Python smoke**, NOT a completed acceptance test. No production enablement, DNA deployment, release or user-data migration was performed.

## Immutable starting refs and dependency graph

| Component | Ref observed | Role |
| --- | --- | --- |
| Music main | bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637 | Existing v1 production line |
| Music #52 | 853ce9800d7a5e4e7a61cd220b5796c9ed817eca | V2 grant implementation; base feat/grant-anchor-v21 |
| Media Core main | 0e0a6290729debdb0d1e87c9201900a901adc102 | Core baseline |
| Media Core #14 | 314b19dec9e506298c2f2ca38c5aebb32d4e3cec | V2 verifier; base feat/grant-anchor-v21 |
| Music #54 | 50704e88d73ce71a4c74c6715095207e8baec62a (before this report) | Isolated mutation hardening |
| Media Core #16 | 2aad791a77332bf2786ca5013e1c46cf73be51e8 | Isolated owner-assurance correction |

PRs #52/#14 depend on grant-anchor/v2.1, S2 v2.1 lifecycle, and the prior Media Core entitlement, binding and canonical JSON work. Parent development PRs are still unmerged into main. The related open PRs and branches were examined to avoid creating a parallel implementation.

## Source audit against docs/ACCESS-GRANT-V2.md §3-§7

All rows mean **implementation inspected**, not conductor acceptance or a passed test.

| Field / invariant | Inspected implementation | Source-review result |
| --- | --- | --- |
| schema | Exact v2 schema and separate envelope in Python and Rust | Matched |
| grant_id | 16-byte lowercase-hex, issuer-generated randomness and DNA earlier-anchor uniqueness | Matched statically; live rejection pending |
| dna_hash | Compared with lifecycle DNA; anchor compared with actual DNA | Matched statically |
| owner_agent | Must match historical manifest owner and lifecycle author | Matched |
| issuer_agent | Must equal owner agent for v2.0 | Matched |
| issuer_purpose | Only owner-manifest | Matched |
| issuer_key_hex | Must equal lifecycle key for named transition | Matched |
| issuer_key_generation | Canonical decimal and matches resolved transition | Matched |
| issuer_key_action | Matches lifecycle generation and public anchor | Matched |
| file_id | Exact historical S1 package ID and commitment | Matched |
| manifest_sha256 | Exact signed historical manifest digest | Matched |
| manifest_key_hex | Exact originally authorised manifest signer, not current issuer | Matched |
| listener_agent | Compared to local authenticated subject | Matched |
| recipient_key_hex | Compared to local X25519 public key, included in signature and wrap context | Matched |
| rights | Sorted, nonempty, duplicate-free subset; operation-specific enforcement | Matched before object mutation finding |
| term | Perpetual or bounded-window policy, no rentals/subscriptions | Matched |
| issued_at | Signed i64 Unix seconds; 120s future tolerance | Matched |
| not_before | Signed i64; equals issuance for perpetual | Matched |
| expires_at | Signed i64; zero for perpetual, 24h maximum stream window | Matched |
| basis | Only owner-decision | Matched |
| entitlement_ref | Empty or 64 lowercase hex; no proof of payment implied | Matched |
| key_wrap | Exact v2 algorithm ID | Matched |
| ephemeral_key_hex | Exact 32-byte public key; bound in signature | Matched |
| salt_b64 | Canonical 16-byte base64, signature-bound | Matched |
| nonce_b64 | Canonical 12-byte base64, signature-bound | Matched |
| wrapped_key_b64 | Canonical 48-byte base64, signature-bound | Matched |
| signature_hex | Strict 64-byte hex; domain-prefixed Ed25519 signed body | Matched |
| grant anchor schema, DNA, ID, commitment, issuer action | Five public fields only; SHA-256 domain commitment; owner source-chain ordering, current unrevoked generation and earlier duplicate scan | Matched statically; real Holochain acceptance pending |

Signed bytes in both languages use the domain holochain-music/access-grant/v2 followed by NUL and sorted, compact UTF-8 canonical JSON. The anchor commitment uses its own domain before hashing that exact signed message; wrapping uses a separate v2-only NUL-terminated domain for both HKDF info and AES-GCM AAD. Only ephemeral wrapping fields are omitted from wrap scope. Verified historical S1 manifest provenance and current anchored grant authority use different lifecycle checks. None of these checks depends on user-claimed timestamps for source-chain order.

Media Core exposes ciphertext key-wrap metadata only; it does not accept a recipient private key or unwrap an S1 plaintext content key. Music's recipient-side private-key unwrapping remains local. These are code/API observations, not a proof of secret non-disclosure on every network path.

## Findings

**F1 — High (corrective draft Music #54): mutable post-verification entitlement.** A frozen Python dataclass held the ORIGINAL mutable grant body. After signature/anchor verification, a caller could alter that dictionary's rights and then have the verified object's authorize method approve rights never signed or anchored. Likewise the returned body was mutable. Correction: retain immutable canonical authenticated body bytes; return defensive copies. A new regression test attempts both source-dictionary and returned-view mutations, denies export, and checks original recipient unwrap. This is a hardening fix to the verifier API; no externally exploitable mutation path is proven.

**F2 — Medium (corrective draft Media Core #16 and Music #54): owner-assurance field provenance.** Both Python and Rust v2 results originally set owner_assurance from the current issuer, contrary to §5 and CORE-005's historical OwnedManifest meaning. That can mislabel a historical manifest where issuer continuity differs after recovery. Corrections: Rust uses content.owner_assurance() while Python derives historical assurance from the original signing generation; current issuer continuity stays separately accessible. Python's recovered-issuer test now asserts historical G1 assurance remains normal under an accepted recovered G3 grant. A Rust divergent recovered-issuer positive vector is still missing.

**F3 — Documented residual risk: stale offline authority view.** Music caches local conductor-derived lifecycle/anchor rows in a JSON evidence file and retries verification offline. Later revocations cannot be learned while disconnected. The cache is not separately sealed against a local filesystem writer; the threat model must treat local storage/process integrity as trusted. Online playback rechecks conductor views, but a conductor may itself be missing later DHT actions. Neither a cached verdict nor a live response guarantees global revocation freshness.

**F4 — Test/gate weakness.** The three-conductor test source exists but is skipped unless explicitly enabled; the test checks exception strings plus bridge liveness rather than proving a typed integrity-zome rejection for every adversarial action. An actual pinned v2.1 DNA test run, including duplicate IDs, revoked issuer, wrong recipient, forged anchor, post-rotation issuance and post-revocation historical continuity, is not evidenced. Additional restart/off-host and recovery tests remain necessary before broader rollout.

**F5 — Cross-PR coverage gap.** The Media Core Rust/Python CI workflow checks out a fixed companion Music branch, not draft correction PR #54. Green checks on the older branch would not prove the post-verification immutability fix. Re-run integrated verification with exact reviewed SHAs and preserve test artifacts.

## Tests and evidential status as of review

| Test / claim | Actual status |
| --- | --- |
| Independent Python cryptographic primitive smoke | **PASSED 13/13** on local cryptography library; reference-only, not repo module or conductor |
| Music test_access_grant_v2.py | **NOT EXECUTED locally**, CI queued |
| Music new mutation regression | **COMMITTED**, not executed |
| Music recovered issuer/historical assurance regression | **COMMITTED**, not executed |
| Rust workspace / v2 tests / v1 entitlements | **NOT EXECUTED locally**, CI queued |
| Rust generated Python vector comparison | **NOT EXECUTED locally**, CI queued; the test skips without the fixture env var |
| Real pinned three-conductor acceptance | **NOT EXECUTED**, unavailable Holochain/hc/bridge toolchain and pinned hApp |
| Actual DNA duplicate/revocation/forgery rejection | **NOT DEMONSTRATED**, no validating-conductor logs |
| Actual successful Bob key unwrap for historical g1 track under g2 grant | **NOT DEMONSTRATED**; modeled Python tests exist but were not executed |
| Legacy v1 grant/licence compatibility | **STATICALLY CHECKED** for dispatcher separation; runtime regression unexecuted |
| Windows compatibility | **CI QUEUED**, no pass |
| Human independent security sign-off | **PENDING** |

The local container has Python cryptography, but its shell cannot resolve github.com and has no cargo, rustc, hc or holochain executable. The independent reference smoke exercises Ed25519 positive/negative, X25519 recipient substitution, AES-GCM tampering, HKDF domain separation, anchor hashing and low-order X25519 denial. It intentionally does not validate Holochain history, full v2 schema parsing, Music's Python implementation, or Media Core's Rust implementation.

## Remaining merge gates / recommended next actions

1. Review and integrate corrections #54 and #16 into their respective v2 development branches **only after** passing language-specific tests and peer review; do not merge into main.
2. Execute Music Python regression suites and Rust workspace tests pinned to the exact corrected commits; run fresh Python-generated Rust vectors, including a recovered-issuer Accept case and both positive and negative policy outcomes.
3. Build and hash-pin the correct v2.1 storage DNA and Music hApp. Run artist/listener/Mallory with three disposable *real* conductors; capture typed DNA validation errors, bridge health, committed chain actions, signed generation, recipient unwrap and encrypted playback.
4. Include compromised-issuer recovery, duplicate ID, wrong agent, wrong recipient, forged anchor, expired streaming windows, missing lifecycle rows and stale offline snapshots. Test both historical authenticity and a *new* grant after rotation; not merely issuer-signature verification.
5. Demonstrate all v1 grants and licences still work under their original v1 rules and no automatic downgrade, automatic migration or new production default has appeared.
6. Re-review privacy and rollback: the public anchor reveals timing/frequency only; preserve immutable chain history, do not delete anchors, turn off **new v2 issuance** on rollback, and retain a compatible v2 reader for existing recipients. No network-wide instantaneous revocation or recall of already unwrapped plaintext is possible.

**Recommendation: DO NOT MERGE MUSIC #52 OR MEDIA CORE #14; DO NOT ENABLE v2 BY DEFAULT; DO NOT CLASSIFY PRODUCTION READY.**

Reference PRs: https://github.com/ConorTttttt/holochain-music/pull/52 ; https://github.com/ConorTttttt/holochain-media-core/pull/14 ; corrections https://github.com/ConorTttttt/holochain-music/pull/54 and https://github.com/ConorTttttt/holochain-media-core/pull/16 .
