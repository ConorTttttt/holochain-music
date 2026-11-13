# S2 key-binding v2 (proof of possession) — opt-in v2 storage DNA

Status: implemented on branch `feat/s2-key-binding-v2`; **not** used by the
app by default; no existing identity or network is migrated. Full design,
threat model, test matrix and migration plan:
`holochain-media-core/docs/S2-KEY-BINDING-V2.md`.

## What changed

| Path | Change |
|---|---|
| `dna/` | **Nothing.** v1 DNA hash `uhC0kkLUOg2uytGWLz_sTeVtfJBqa0criBmAYAPwAIUhoDp_9G4RV` reproduced. |
| `dna-v2/` | Separate workspace → `music_storage_v2` (hash `uhC0k_-f-D4bF9w53gD2jXkA4RqYQ_bf0dRdF8rMkJG_tS8WGRamb`). Integrity = v1 rules + `SigningKeyBindingV2` with proof verification; v1 bindings refused. Coordinator = unchanged v1 source + `key_binding_v2_context`, `register_signing_key_v2`, `get_signing_keys_v2`. |
| `holochain_storage/holochain_identity.py` | `key_binding_v2_message`, `make_key_binding_v2` (signs locally), `key_for_agent_v2`, `resolve_signing_key` (explicit `ASSURANCE_POP_V2` / `ASSURANCE_LEGACY_V1` policy). |
| `holochain_music/artist.py` | `ArtistService(key_binding="v2")`: sign the proof locally, register, re-read and verify; refuse conflicting keys. Default `"v1"`. |
| `music-e2e/src/bin/music_app_bridge.rs` | Routes the three v2 functions (no private key passes). |

## Why a separate workspace

Even declaring a cargo feature on the v1 crates changes their metadata hash,
symbol names, the integrity wasm and so the DNA hash; shifting v1 source lines
does too (`wasm_error!` embeds line numbers). `dna-v2/` therefore has its own
crates and a copy of `dna/Cargo.lock`. `v1_rules_unchanged` guards the shared
validation code against drift.

## Proof message

`"holochain-storage/key-binding-pop/v2\0"` followed by, for each of
`schema, dna_hash, agent, purpose, signing_key_hex, generation`, a 4-byte
big-endian length and the UTF-8 bytes. Signed with the key being bound.

## Build and test

```bash
cd dna-v2 && cargo test -p music_storage_integrity_v2 \
  && cargo build --release --target wasm32-unknown-unknown && hc-dna pack workdir
python -m unittest tests.test_s2_key_binding_v2
```

Real-conductor tests (forged bindings refused by the integrity zome, v2
discovery, full v2 retrieval + CORE-005 + decrypt) live in Holochain Media
Core's `integration/core-e2e` (`s2_key_binding_v2`, and `core004_acceptance`
with `CORE_S2_KEY_BINDING=v2`).

## Outstanding

Rotation/revocation, `replica-receipt/v2` (host-attributed receipts),
switching the app bundle and catalogue resolution to the v2 DNA, and any
migration of real users (design only; must be reviewed before use).
