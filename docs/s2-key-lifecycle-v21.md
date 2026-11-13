# S2 key lifecycle v2.1: opt-in v2.1 storage DNA

Status: implemented on branch `feat/s2-v21-key-lifecycle` (from
`feat/s2-key-binding-v2` @ `17a6276`). **Not** used by the app by default.
No existing identity, key or network is migrated, and nothing is deployed.

The full design is in `holochain-media-core/docs/S2-KEY-LIFECYCLE-V21.md`:
threat model, authority model, signing formats, historical policy,
compromised/lost-key procedures, migration and rollback, and the
real-conductor results.

## What changed

| Path | Change |
|---|---|
| `dna/`, `dna-v2/` | **Nothing.** Both rebuild to their recorded hashes. |
| `dna-v21/` | A third, separate workspace that builds `music_storage_v21`. **Integrity:** v1 rules, plus `KeyTransitionV21` and `KeyRevocationV21` validated in chain order against the author's own source chain (`must_get_agent_activity`); v1 and v2 bindings are refused. **Coordinator:** the unchanged v1 source plus `key_lifecycle_v21_context`, `publish_key_transition_v21`, `publish_key_revocation_v21` (deliberately check-free), `get_key_lifecycle_v21` (records with chain positions) and `get_action_position_v21`. |
| `holochain_storage/key_lifecycle.py` | Local signing of inception, rotation, recovery and revocation entries; reader-side `resolve_key_lifecycle` and `evaluate_key`, returning `Active`, `Rotated`, `Revoked`, `HistoricalOnly`, `Ambiguous` or `Invalid`; `replica-receipt/v2` signing and verification (`replicate_package_v2`, `verify_replica_receipt_v2`). |
| `holochain_music/keys.py` | `KeyStore.lifecycle_ed25519(role, generation)`. Generation 1 is the existing key file. Later generations are new files, created before they are published. |
| `holochain_music/artist.py` | `ArtistService(key_binding="v2.1")`: inception with the existing key, `rotate_key_v21` and `revoke_key_v21`. New operations sign with the active key, and hosting signs a v2 receipt. Grants refuse content whose manifest key is no longer active. |
| `music-e2e/src/bin/music_app_bridge.rs` | Routes the v2.1 functions. No private key passes through the bridge. |
| `tests/test_s2_key_lifecycle_v21.py` | Message formats, rotation/recovery/revocation rules, adversarial cases, receipts, and `ArtistService` v2.1. |

The default stays v1: `ArtistService()` and the S1 `replicate_package` are
unchanged, and so are the S1 receipt and the S10 grant formats.

## Key rules, in short

* **Authority.** The Holochain agent (the action author) is the only
  authority for a lifecycle step.
  * Each new key proves possession over the complete transition.
  * A rotation also needs a continuity signature by the old key.
  * A recovery has none, and is labelled `recovered-without-continuity`.
* **Current key.** The "current" key is the last transition on the agent's
  own chain for that purpose, never a timestamp. No skipped generations,
  forks, key reuse, or cross-purpose or cross-DNA reuse.
* **Revocation scope.**
  * `new-operations`: history stays verifiable.
  * `compromised`: only artifacts anchored on the agent's chain before the
    key ended stay verifiable.
* **Receipts.** A `replica-receipt/v2` names the host agent, the exact host
  key generation, the DNA, the owner and the manifest. It proves a historical
  acceptance, not current storage.

## Known limitation

S10 grants are signed by the manifest's key. After a rotation, new grants for
older tracks need those tracks re-published under the active key; the app
refuses rather than sign with a rotated key. A versioned grant format with
its own issuer is needed before rotation is transparent to paid access.
