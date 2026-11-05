# S2 implementation: Holochain-validated storage metadata (work in progress)

This milestone keeps **all ciphertext, full manifest bodies, full storage receipts, and content keys off the Holochain DHT**. The DNA records only small, public, indexable commitments.

## Why two signatures?

1. **Holochain action signature:** only the agent whose key authored a DHT action may register that agent's key-binding entry or file commitment. Only a storage node can author its own storage claim. This is enforced in the integrity zome (not by trusting a client-supplied `agent` string).
2. **S1 Ed25519 signature:** owner signs the complete encrypted file manifest; storage node signs the complete receipt after copying every encrypted chunk. A separately registered public Ed25519 key lets clients authenticate those existing S1 formats. The host still never receives the file content key.

The two signing keys are independent by design; do **not** export Holochain's agent private key to the Python application. Registration binds the public S1 signing key to the Holochain action author, and the actual manifest/receipt signature demonstrates possession of that S1 key.

## DNA entries

| Type | Authorship | Public data | Security guarantee |
| --- | --- | --- | --- |
| `SigningKeyBinding` | Agent in `agent` | Scheme/purpose, 32-byte Ed25519 public key as lowercase hex | The Holochain agent authored the key binding |
| `FileCommitment` | `owner_agent` | Random file ID and SHA-256 of signed manifest | Owner committed to that exact signed manifest |
| `ReplicaClaim` | `node_agent` | Owner/file ID, manifest digest, SHA-256 of complete signed receipt | Node authored this receipt commitment; **not** proof of continuing storage |

All entries are append-only. The integrity zome rejects updates/deletes and author mismatches. No authority is inferred from unverified strings in entry bodies.

## Coordinator API

- `register_signing_key(SigningKeyBinding) -> ActionHash`
- `get_signing_keys(AgentPubKey) -> Vec<AuthoredRecord<SigningKeyBinding>>`
- `publish_file_commitment(FileCommitment) -> ActionHash`
- `get_file_commitments(AgentPubKey) -> Vec<AuthoredRecord<FileCommitment>>`
- `publish_replica_claim(ReplicaClaim) -> ActionHash`
- `get_replica_claims({owner_agent,file_id}) -> Vec<AuthoredRecord<ReplicaClaim>>`

The `AuthoredRecord` wrapper contains the `Record` action's **actual** author and action hash as observed by the local Holochain conductor. A host cannot prove possession by fabricating its own `author` string in a HTTP response.

## Python verification boundary

`holochain_storage.holochain_identity` consumes `AuthoredRecord` objects with author and action hash originating in a **trusted, locally connected and validating Holochain conductor**. It checks the identity/key purposes, signed S1 manifest and receipt, and all hashes and file IDs.

**Critical:** `AuthoredRecord` is a data-transfer representation, NOT a self-authenticating proof. Constructing one from arbitrary remote JSON provides no authentication. The trusted Holochain conductor/record provenance must be established by a separate bridge and tested. Do not treat a mock as a working Holochain integration.

## Build the two zomes

Requires Rust/Cargo with `wasm32-unknown-unknown` target, `hc` CLI compatible with Holochain 0.7.0 and the 0.7/0.8 stable `hdk`/`hdi` dependency versions (matches the working Holochain MOQ DNA baseline).

```bash
cd dna
cargo test -p music_storage_integrity
cargo build --release --target wasm32-unknown-unknown
hc dna pack workdir
hc app pack workdir
```

The Rust zomes in this PR are untested against a real conductor until CI type checking and two-conductor integration tests pass. Python tests cover the record verification **contract** only.

## Required two-conductor acceptance test (not yet implemented)

1. Boot **Alice** and **Bob** on independent conductors with this DNA installed; wait for gossip.
2. Alice publishes her own `owner-manifest` key binding and a `FileCommitment` corresponding to a signed S1 package.
3. Bob reads the key binding and commitment from Holochain and verifies the complete S1 manifest and chunk digests.
4. Bob independently copies the encrypted file, registers a `host-receipt` key binding and publishes a `ReplicaClaim` for his signed receipt.
5. Alice discovers Bob's claim through the second conductor, retrieves/validates the signed receipt off-DHT, and checks its hash and signer against Bob's Holochain-authored key binding.
6. Forge attempts: Alice trying to register a key/commitment in Bob's name, Bob forging Alice's commitment, or Alice submitting a claim as Bob must be **rejected by the conductor's integrity zome**.
7. Confirm DNA entries and links hold **no encrypted chunks, full manifests, full receipts or secret keys**.

This is the gate before S2 is considered complete. This PR is **foundation code and tests**, not the complete acceptance milestone.

## Known limitations

- The signing-key registry allows multiple keys per agent/purpose (rotation/revocation and selection policy not yet designed). A client must not trust arbitrary candidate keys or make first-seen assumptions without a clear policy.
- Host storage and the off-DHT receipt transfer aren't networked yet, and there is no storage availability proof.
- No conductor-authenticating Python bridge exists yet; local `AuthoredRecord` test objects simulate the returned shape only.
- No real two-conductor test or gossiped DHT verification has run; zome compilation needs CI validation.
- A claim to store someone else's file does not mean the owner authorised it or that the file exists; clients must independently validate the owner commitment and signed manifest before treating a host claim as usable.
- Denial of service, DHT indexing abuse and unbounded key rotation require operational hardening.

[Track S2 in GitHub issue #2](https://github.com/ConorTttttt/holochain-music/issues/2).
