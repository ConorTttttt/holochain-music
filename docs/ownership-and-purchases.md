# Permanent music purchases

## Product principle

A listener who buys a song should obtain a **real downloadable copy** that continues to work when Holochain Music, the artist, and the storage network are offline.

The buyer should be able to decrypt/export the original audio file, play it in ordinary offline software, and make the personal backups permitted by the licence. This is not a licence-server-controlled streaming token.

A purchase of a copy is **not** by default a transfer of copyright in the recording or composition. The artist must have the rights to grant the chosen licence. Redistribution and resale rights are separate decisions.

## Proposed purchase flow

1. Artist registers a music release, signed encrypted package manifest, licence terms and sale offer.
2. Buyer pays artist; a settlement service/protocol verifies completion. **Payments are not implemented yet.**
3. Artist signs a durable purchase receipt and a **perpetual-personal-use** grant scoped to the manifest and buyer public key.
4. Artist encrypts the content key for the buyer, for example using ephemeral X25519 key agreement, HKDF-SHA256, and authenticated encryption. Neither Holochain nor hosting nodes receive plaintext keys.
5. Buyer retrieves encrypted chunks from any complete replica and verifies artist signature, ciphertext hashes and authentication tags.
6. Buyer uses their private key to unwrap the content key, decrypts and exports the original file, and maintains their own backups.
7. Buyer can keep the signed licence/grant for evidence and future recovery, but playback must never depend on an online licence check.

## Distinguish product modes

| Feature | Stream access | Permanent purchase |
| --- | --- | --- |
| Playback while authorised | Yes | Yes |
| Offline independent exported file | Not guaranteed | Yes |
| Future access grant can expire | Possible | No, personal-use grant non-expiring |
| Platform must remain online after export | Possibly | No |
| Copyright transfers | No | No, unless expressly negotiated |

## Constraints

- Granting someone an exportable file cannot prevent copying; do not describe it as DRM.
- Revoking old access cannot revoke an already exported offline copy.
- Lost buyer keys can make encrypted-only backups unusable; promote private-key recovery and plaintext personal backups.
- Refunds/chargebacks, privacy of purchase records, licence versions, rights disputes, tax, and settlement need explicit treatment.
- The ability to cryptographically produce a buyer grant is **not proof of payment**. Production must authenticate the seller and verify settlement before creating grants.
