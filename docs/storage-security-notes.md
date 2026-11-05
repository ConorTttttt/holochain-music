# S1 security and threat-model notes

Status: **prototype only; not independently audited**. The system assumes the file-owner client and its operating system are honest. Storage hosts are untrusted for confidentiality and stored-byte integrity; they are not trusted to keep data available.

## Assets and trust boundaries

- **Secrets:** content encryption key, artist signing key, buyer private decryption key. None should be in Holochain entries, storage-node receipts, logs or public GitHub repositories.
- **Public authenticated data:** signed manifest, ciphertext hashes, storage-node acceptance receipts, buyer's *public* encryption key (only if its disclosure is acceptable).
- **Untrusted hosts:** can copy, delete, withhold or corrupt encrypted chunks, lie about their availability and issue misleading signed receipts. They cannot normally decrypt an uncompromised AES-GCM package without the content key.
- **Application identities:** v1 local tests pin raw Ed25519 public keys. Holochain `AgentPubKey` binding and rotations are S2; a self-declared signer is never sufficient authentication.

## Protection present now

1. Locally generated per-package random AES-256-GCM key; per-chunk independent 96-bit nonce. Package ID and chunk index included as authenticated additional data.
2. Every ciphertext chunk has a SHA-256 address. The artist signs a canonical JSON manifest listing exact chunk indices, nonces, sizes and hashes. Nodes verify full packages before issuing acceptance receipts.
3. Storage-node receipt signature is checked against an expected externally pinned node key; receipt includes the exact signed-manifest digest and file ID.
4. Local importer and verifier have per-chunk and overall file/manifest limits. Verification refuses symlinked object files (not a substitute for a hardened storage service).
5. Offline buyer grants bind a wrapped 32-byte content key to a manifest and buyer X25519 key, using ephemeral X25519, HKDF-SHA256 and AES-256-GCM. A grant is **not** evidence of payment.

## Remaining threats, operational gaps and controls

| Threat / gap | Current result | Required production response |
| --- | --- | --- |
| Storage node deletes data after signing | Receipt is still valid but data may be unavailable | Fresh challenges, meaningful retrievability audits, replica repair and durable contracts |
| Storage node fetches from another node during a challenge | Challenge can succeed without local custody | Define required service guarantees and be cautious about claims of storage independence |
| Lost artist content key or buyer private key | Encrypted package / grant may become unusable | OS-backed secret storage or encrypted vault, recovery and device migration; allow buyer plaintext backups |
| Forged host/owner identity | Raw public key can be self-declared in this prototype | Holochain agent binding with validation, verification at discovery time, key rotation/revocation |
| Dishonest signing node | Can sign an acceptance claim it never fulfilled | Audits, incentives, evidence and reputation/penalties; signatures do not guarantee truth |
| Host can learn file size and access timing | Not hidden | Optional padding, traffic privacy and private metadata design |
| Buyer redistributes plaintext after export | Crypto cannot prevent it | Clear licence, rights enforcement and marketplace policies, not fictitious DRM |
| Local filesystem is adversarial | Directory symlink/race attacks not comprehensively addressed | Dedicated sandbox user, no shared writable storage directories, atomic openat/dirfd discipline and OS file permissions |
| Large/malicious inputs | v1 per-chunk and manifest bounds exist, but client still processes arbitrarily much work up to caps | Quotas, streaming ingestion and resource budgets, request throttling and input-format fuzzing |
| Payment or copyright dispute | Neither is implemented | Separate verified settlement and proof of the artist's licensing authority |
| Crash/power loss during file write | File is fsynced, but directory metadata and multi-file transaction are not durably committed | Directory fsync, recovery journal, atomic commitment and proven crash semantics |
| Network or storage-node attack | No actual server in S1 | Authenticated transport, replay prevention, protocol fuzzing, secure key handling and external security review |

## Software scope and source of truth

- GitHub: [holochain-music](https://github.com/ConorTttttt/holochain-music)
- Milestone [S1 issue](https://github.com/ConorTttttt/holochain-music/issues/1)
- Phase S2 will connect identities and metadata to a real Holochain DNA; phase S3 will address availability and buyer access end-to-end.
