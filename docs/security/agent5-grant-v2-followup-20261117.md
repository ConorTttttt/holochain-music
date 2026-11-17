# Agent 5 — grant-v2 immutability follow-up and acceptance evidence (17 November 2026)

**Decision: NO-GO.** Opt-in grant-v2 stays outside Music RC1. No main-branch merge, DNA deployment, data migration or production trust-policy relaxation is authorised here.

## Refs reviewed

- Music main: `bd7aabc3e9ea1fef1e8e8f674301e1b5ffecb637`.
- Music #52: `853ce9800d7a5e4e7a61cd220b5796c9ed817eca` (base `feat/grant-anchor-v21` at `b4173fc31317e8563f6f7bd18de73dbe5c47f014`).
- Music #54 prior head: `b4d7c00ff190487f74f59ae521e85312ce6b0d0d` (stacked on #52).
- Core main: `0e0a6290729debdb0d1e87c9201900a901adc102`.
- Core #14: `314b19dec9e506298c2f2ca38c5aebb32d4e3cec` (base `feat/grant-anchor-v21` at `a74a8aec32da03962788ad92810c413103b2ffd3`).
- Core #16: `2aad791a77332bf2786ca5013e1c46cf73be51e8` (stacked on #14).
- Upstream v2.1 lifecycle, grant-anchor DNA and v1 compatibility branches are unmerged; retain existing DNA hash identities, licence formats and recipient unwrap semantics.

## New finding: in-flight mutation after signature/anchor check

Before this change, Music #54 retained immutable bytes **only when returning** `VerifiedAccessGrantV2`. For a caller-provided dict, `parse_access_grant_v2` returned the original object. The verifier then computed the signed message, validated signature/anchor, checked terms and finally snapshotted `canonical(b)`.

A concurrent or callback-mediated edit to `grant["body"]["rights"]` **after authenticating the original message but before verdict construction** could therefore cause the returned verified object to report unsanctioned rights. The existing regression covered mutation *after* verdict construction, not while verifying.

**Correction:** canonicalise and re-parse into an independent body snapshot **before** authorisation checks; perform signature, anchor, terms and final `VerifiedAccessGrantV2` construction against that single copy. Add a regression that deliberately changes the original source dict in the anchor-verification callback, upgrading `["stream"]` to all perpetual rights and swapping the recipient key, then asserts export remains denied and original Bob unwrap remains valid. The test uses modelled `SequencedRecord` anchor evidence; it is not a conductor acceptance claim. No on-wire format, HKDF domain, schema, v1 code or DNA changed.

This narrows the race inside the Python verifier. It is **not** a claim of protection from malicious code with arbitrary access to the interpreter, forged local-conductor evidence, or filesystem tampering.

## Independently inspected CI evidence (at inspection)

- Music #54 Python 3.12: [storage protocol run 44080060193](https://github.com/ConorTttttt/holochain-music/actions/runs/44080060193) included **525 tests, 51 skipped**, successful. Nine `test_access_grant_v2.V2ContractTests` cases passed at its previous head, including the original mutation and recovered-G3 assurance cases. The three `test_access_grant_v2_real_conductors` tests were **skipped** because `HOLOCHAIN_MUSIC_V21_E2E` was not enabled. The new in-flight mutation regression above was **not yet executed** at report creation; inspect new CI independently.
- Core #16 [Rust workspace run 44079219453](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44079219453) failed its rustfmt gate (numerous differences in the v2 Rust files), not a demonstrated language semantic mismatch.
- Core #16 [cross-language run 44079219398](https://github.com/ConorTttttt/holochain-media-core/actions/runs/44079219398) generated and uploaded Python vectors, then failed the broad Rust suite (**51 passed, 21 failed**) because legacy S1 `MUSIC_VECTORS` was unset. The workflow sets `MUSIC_ACCESS_GRANT_V2_VECTORS` but not the older shared S1 fixture. Fix workflow fixture setup or narrow the exact Rust target, then rerun; do not reinterpret this failure as passing Rust/Python agreement.
- The Core workflow checks out Music `feat/access-grant-v2-agent6`, NOT the #54 correction. Cross-language success must be measured with *pinned corrected heads*.
- No local repo checkout can be fetched from the current agent shell (GitHub DNS unavailable); there is no local `rustc`, `cargo`, `hc` or `holochain` binary. No local Music pytest, Rust cargo or real conductor test has been run in this follow-up.

## Remaining gate: three real independent conductors

The present three-conductor test uses real app bridge calls if enabled, but asserts denial through exception text and bridge responsiveness; it does not independently establish typed validation-zome rejection for each adversarial action. Before a GO decision:

1. Agent 4 must correct Rust fixture setup/formatting and add Python-generated Rust **recovered-issuer accepted** vectors proving `content.owner_assurance() != issuer.assurance()` when appropriate.
2. Pin the exact Music/Core corrected SHA pair; run the full Music Python v2 security suite, Core Rust tests, positive and negative cross-language vectors, and legacy v1 regressions.
3. Build/hash-pin the exact v2.1 hApp; run three disposable artist/listener/attacker conductors. Capture validated chain action hashes, typed integrity denials for forged anchors and duplicate grant IDs, and post-revocation issuer rejection. A Python exception string alone is insufficient.
4. Verify successful post-rotation issuance for an original signed S1 manifest, recipient-only X25519 unwrap, wrong recipient/rights rejection, resumed/restarted verification and offline-snapshot limits.
5. Review stale authority views: locally cached JSON snapshots are not separately sealed; offline revocations may be invisible, and a conductor may not have received every latest DHT action. Preserve fail-closed policy, append-only anchors and a compatible existing-v2 reader on rollback; stop new v2 issuance, do not attempt to delete historical anchors.
6. Require an independent reviewer to verify all evidence before marking #54/#16 ready, and keep #52/#14 draft and out of RC1.

**Status of new change:** source and test are committed for CI verification; do not count the new test as passing until the updated check result is inspected.
