# Encrypted storage v1 — full replicas (Model A)

**Scope:** file-type-independent storage. Music is only one application. This protocol is a starting design, not an audited implementation.

## Data boundaries

- File owner/client encrypts the source file locally.
- Storage nodes hold **complete encrypted copies**, never plaintext keys.
- The Holochain DHT holds identities, metadata, signed storage commitments and discovery information, not file content.
- MoQ/QUIC will eventually transfer encrypted file chunks on demand; the existing live stream's bounded/latest-packet retention is unsuitable for reliable seeking and replay.

## Packaging and verification

1. Generate a random 256-bit content key and random package ID.
2. Split opaque input bytes into independent chunks (prototype default 256 KiB).
3. Encrypt each chunk with AES-256-GCM using a unique random nonce and authenticated package-ID/chunk-index context.
4. Compute SHA-256 for every **ciphertext** chunk. Address stored objects by ciphertext hashes.
5. Create a versioned canonical manifest listing package ID, cipher, ciphertext digests, nonce and chunk lengths.
6. Sign the manifest with the owner's verified signing identity; keep the content key outside the public manifest.
7. Each host verifies manifest signature and **every** encrypted chunk against the manifest; it stores a full replica.
8. Each host issues a signed receipt binding its identity, the exact manifest digest, accepted file ID, chunk count and timestamp.
9. A client verifies that the receipt's signer is the *expected* node key, not merely a self-declared signature.

Fresh per-file keys/nonces prevent deterministic equality leakage across separate packages. Ciphertext size, package length, and some metadata remain observable. Padding and metadata protection are future concerns.

## What a receipt proves

A signed receipt is an **assertion of successful receipt and verification at one time**. It does not prove ongoing storage, that a node keeps its own independent copy, or that the file will be available later. Build challenge-response and meaningful proofs of retrievability separately. Random ciphertext chunk audits detect some loss but are not, by themselves, a rigorous PoR.

## Long-term availability

First use complete replicas on multiple nodes. Later: availability measurements, repair and redelivery, encryption-key rotation, authenticated host identity, economic incentives, and optionally erasure coding.

## Reusable interface (target)

```text
create_encrypted_package(bytes) -> signed_manifest + owner_secret
store_replica(signed_manifest, encrypted_chunks) -> signed_receipt
verify_replica(signed_manifest, encrypted_chunks) -> integrity_result
challenge_replica(challenge_nonce, chunk_positions) -> verifiable_response
retrieve(signed_manifest, range) -> authenticated_encrypted_chunks
decrypt_offline(signed_manifest, chunks, owner_secret) -> original_file
```

## Security / availability gaps before production

No trusted key custody or recovery, no Holochain signing-key binding, no MoQ on-demand chunk protocol, no host service, no live challenge/audit protocol, no storage guarantees, no payments, and no independent security review.
