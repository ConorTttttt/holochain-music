# Holochain Music

A decentralised music app built on [Holochain MOQ](https://github.com/ConorTttttt/holochain-moq), with a **reusable, file-type-independent encrypted storage layer**.

## Starting architecture: Model A — complete encrypted replicas

An artist or file owner encrypts an arbitrary file locally, signs a manifest of its encrypted chunks, and sends **complete encrypted copies** to one or more storage nodes. Nodes verify the encrypted bytes against the owner's signed manifest and issue signed acceptance receipts. Nodes **do not** receive plaintext content keys.

- **Holochain:** identities, artist/album/track metadata, rights/licence records, discovery, and storage receipts or commitments. Never bulk file bytes or unencrypted content keys.
- **Generic storage:** opaque encrypted chunks, content hashes, full replicas, verification and later proof-of-retrievability audits.
- **MoQ/QUIC:** eventual authenticated transfer of encrypted chunks. Existing live media streams are not a seekable on-demand file protocol.
- **Music app:** music catalogue, player, licences, purchase settlement and user experience.

## Purchases and true offline use

A permanent music purchase is designed to deliver a **non-expiring personal-use licence** and the encrypted key material needed for a buyer to export a real, usable file. Once saved, a buyer can listen, transfer it among their devices and make permitted backups without the app, network, artist or storage node remaining online.

This is **ownership of a usable copy under licence**, not ownership of the sound-recording or composition copyright. A purchase does not automatically grant redistribution, commercial usage, or resale rights.

## Status

Design committed. The initial local prototype separately demonstrates AES-256-GCM file chunking, Ed25519-signed manifests and storage-node receipts, X25519-wrapped buyer keys, full replication, integrity verification, and offline file reconstruction. The prototype is **not** a deployed network, payment system, Holochain DNA, MoQ on-demand server or independent proof of long-term storage.

See [storage protocol](docs/encrypted-storage-v1.md) and [purchase model](docs/ownership-and-purchases.md).

## Security principles

1. Keys must never appear in public manifests or storage receipts.
2. Signatures are meaningful only when keys are pinned to an authenticated Holochain identity.
3. A signed receipt demonstrates acceptance, **not proof of continuing custody**.
4. Fully usable offline files cannot be cryptographically revoked after export.
5. File-size limits, secure key backups, replay-safe storage challenges, abuse protection and payments need production design and review.

No software licence has been selected yet.
