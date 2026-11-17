# Agent 6 — access-grant/v2 multi-conductor acceptance and rollback

**Status: NOT YET ACCEPTED.** Companion Music PR #52 and Media Core PR #14
are **drafts**. v2 is P1 opt-in protocol work and is NOT an RC1 gate.
This report distinguishes implemented tests from executed evidence. Until
passing CI, three-conductor results and review are attached, the release
gate remains **RED**.

## Decisions reviewed before implementation

Source of authority: Media Core docs/ACCESS-GRANT-V2.md; S2 v2.1 lifecycle,
grant-anchor and private-grant security reviews. The owner agent is the
lifecycle/DNA action author. An Ed25519 signing key alone never owns a track.

1. Immutable S1 manifest signer is verified against the generation valid at
   the original owner-authored file commitment. It is never replaced in
   plaintext or re-signed to issue a later grant.
2. NEW access-grant/v2 uses the current authorised owner-manifest lifecycle
   generation at the **validated grant anchor's action sequence**. The
   private signed message is bound to the public anchor by domain-separated
   SHA-256. A public anchor alone is not an entitlement.
3. The exact signed message binds DNA, owner and issuer, key action/generation,
   package, canonical manifest digest and historical signer, listener,
   recipient X25519 key, rights, term, issuance/validity and wrapping context.
4. Default recovered-lineage policy: **reject**. Normal rotation with
   predecessor continuity is accepted when chain ordering permits.
5. Content key is wrapped by X25519/HKDF-SHA256/AES-256-GCM in the issuer
   process. Only the recipient may unwrap. The public anchor, Music metadata
   services, Holochain DHT, CAS, MoQ host and Media Core never receive it.
6. No payments, rentals or subscriptions; no v1 DNA mutation; no implicit
   fallback from v2 to a weaker grant/identity policy.

## Deliverables

- Music: separate v2 envelope, exact-field validation, signed rights, issuance
  after rotation, validated conductor commitment positions, anchored delivery,
  recipient verification, playback and export gates, and a local-only offline
  authority snapshot.
- Media Core: strict v2 verifier, separate issuer-key assurance and dynamic
  rights, mandatory valid anchor, no key unwrap, and an explicit refusal to
  handle v2 through the legacy v1 entitlement dispatcher.
- Music tests: tests/test_access_grant_v2.py, and
  scripts/generate_music_access_grant_v2_vectors.py.
- Cross-language check: Media Core
  crates/content-core/src/access_grant_v2_vectors_tests.rs, consumed by
  .github/workflows/access-grant-v2.yml. The Media Core CI workflow checks
  out the companion Music branch, generates fresh vectors using Python,
  verifies them with independent Rust code and uploads the JSON artifact.
- Three-conductor gate: Music
  tests/test_access_grant_v2_real_conductors.py (artist, listener, Mallory).

## Execution record — do not infer passes

| Gate | Evidence status | Pass requirement |
| --- | --- | --- |
| Rust workspace compile and tests | **PENDING / not evidenced** | Existing core suite, all v1 tests, and new v2 tests pass |
| Python grant/rotation unit tests | **PENDING / not evidenced** | All positive and negative tests pass |
| Rust/Python agreement | **PENDING / not evidenced** | Same signature bytes, wrap AAD and outcome for every generated vector |
| v1 grants and licences | **PENDING / not evidenced** | Existing catalogue and application tests remain green |
| Three real conductors | **NOT RUN in this agent session** | Real validated actions; real MoQ delivery and recipient verification |
| Duplicate grant-id anchor | **NOT RUN in this agent session** | DNA validation rejects second author action, not timeout |
| Compromised revocation before new anchor | **NOT RUN in this agent session** | DNA and recipient reject new issuance |
| Historical grant prior to revocation | **NOT RUN in this agent session** | Past valid anchor remains valid by ordering |
| Recovery default refusal | **PENDING / not evidenced** | Both languages reject recovery without continuity by default |
| Independent security review | **NOT STARTED** | Approval covering threat model, privacy, and rollback |

An integration-suite source file or a queued Actions run is NOT a pass.
See exact run/job URLs in the companion draft PR checks once available.
Do not claim the acceptance gate is green until there are captured logs.

## Reproduce

From an isolated Music worktree on feat/access-grant-v2-agent6:

    python -m pip install -e .
    python -m unittest discover -s tests -p test_access_grant_v2.py -v
    python scripts/generate_music_access_grant_v2_vectors.py > /tmp/music-v2-vectors.json

From the companion Media Core worktree on feat/access-grant-v2-agent6:

    export MUSIC_ACCESS_GRANT_V2_VECTORS=/tmp/music-v2-vectors.json
    cargo test -p holochain-content-core --all-features

For the three real-conductor check, first build and pin the **v2.1** storage
DNA/hApp and all Music bridge/MoQ binaries, then run **only against isolated
disposable conductor homes**:

    export HOLOCHAIN_MUSIC_HAPP=/absolute/path/to/your/v21-happ
    export HOLOCHAIN_MUSIC_V21_E2E=1
    python -m unittest discover -s tests -p test_access_grant_v2_real_conductors.py -v

The real suite exercises: historical g1 manifest and commitment; normal
rotation to g2; fresh private grant and public anchor; Bob acceptance of g2
grant for g1 track and recipient unwrap; Mallory unable to author Alice's
anchor; duplicate grant-id refused by DNA; post-anchor compromised
revocation preserves prior grant; revoked g2 cannot issue again. Every DNA
denial must be a typed conductor rejection and the bridge must remain
healthy after the attempted call. Add and capture off-host and restart cases
before declaring multi-machine rollout ready.

## Migration

No in-place DNA conversion and no automatic v1->v2 grant translation.
Keep legacy v1 storage DNA, S1 manifest digest, signed chunks, v1 licences
and private inbox unchanged. To opt in on a **separate test profile with a
pinned v2.1 hApp/DNA**, set:

    key_binding = "v2.1"
    access_grant_v2 = true

This is an application-local configuration; both default to v1 / false.
An artist must prove the historical signer is a generation in its verified
v2.1 lineage, and the original file commitment must have a validated chain
position before the first rotation; copying an unrelated v1 signing key into
v2.1 without validated provenance is NOT an automatic migration.
New grants can coexist with old v1 licences (no rewriting existing grants).

The recipient library caches only a **locally verified conductor snapshot**
for offline use, never a sender-authored authority assertion. An offline
snapshot cannot learn newer revocations; clients must re-verify against the
local validating conductor on next online use. This is a deliberate offline
limitation, not a claim of always-current network status.

## Rollback

1. Disable **new issuance** with access_grant_v2=false; leave v1 mode and
   pre-existing v1 licences intact. Do not delete DHT anchors or lifecycle
   entries (immutable chain audit trail).
2. Preserve existing v2 encrypted grants and local verified evidence on
   recipients. A v1-only client cannot read a v2 grant; provide a compatible
   opt-in reader or explicitly re-issue a permitted v1 licence for content
   whose signer is still active under v1 rules. Do not silently reinterpret
   v2 as v1 or force republishing of legitimately historical content.
3. If compromised-key policy changes, re-review historic validity, revoke
   the generation through Holochain as appropriate, and verify the network
   before issuing any new grant. Rotation/recovery history must not be
   rewritten, and a recovery issuer stays refused by default.
4. To revert these PRs, revert only their additive code and explicit
   opt-in settings on the development branch; retain the v2.1 DNA chain
   and immutable S1 package. No RC1 migration/rollback is required.

**Merge gate:** DO NOT MERGE until the table above has independently
captured passing evidence and a reviewer signs off on scope, anti-replay,
offline cache, and lifecycle order.
