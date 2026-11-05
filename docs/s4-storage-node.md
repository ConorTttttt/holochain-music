# S4: Networked encrypted storage node — first implementation

**Scope: prototype only.** This is a real long-running HTTP service with persistent disk storage, compatible with S1's Python encrypted file format and signed receipts. It is not a production multi-tenant service, not directly connected to Holochain, and not MoQ yet.

## Quickstart

Prerequisites: Rust stable and Python >=3.10. From the repository root:

```bash
python -m pip install -e .
python -m holochain_storage.keygen --out ./dev-artist.key
# Copy the printed artist Ed25519 PUBLIC key (base64) into ARTIST_PUB:
export ARTIST_PUB='PASTE_BASE64_PUBLIC_KEY_HERE'
cargo run --manifest-path crates/storage-node/Cargo.toml -- \
  --root ./private-node --artist-key "$ARTIST_PUB" --listen 127.0.0.1:4780
```

The server prints its **node** Ed25519 public key. In another terminal:

```bash
python -m holochain_storage.network_demo /path/to/your/own/file \
  --artist-secret ./dev-artist.key \
  --node-key PASTE_NODE_PUBLIC_KEY_HERE \
  --node http://127.0.0.1:4780
```

The demo creates an S1 encrypted package, signs and uploads its manifest, streams ciphertext chunks individually, requests the node's signed full-replica receipt, downloads and verifies all ciphertext again, and exports an exact offline plaintext copy to a temporary location. **It never sends the content key to the node.**

## API v1 (HTTP, localhost-only by default)

| Endpoint | Action | Authorization |
| --- | --- | --- |
| `GET /health` | Readiness check | Public |
| `POST /v1/packages/init` | Validate artist-signed manifest; create resumable staging record | Artist-signed request |
| `PUT /v1/packages/:id/chunks/:index` | Verify one ciphertext chunk hash and byte length, atomically persist | Artist-signed request |
| `POST /v1/packages/:id/commit` | Verify **all** chunks and issue node-signed S1 receipt | Artist-signed request |
| `GET /v1/packages/:id/manifest` | Read pinned artist-signed manifest of committed file | Public ciphertext metadata |
| `GET /v1/packages/:id/receipt` | Read node-signed acceptance claim | Public |
| `GET /v1/packages/:id/chunks/:index` | Retrieve ciphertext by signed manifest index | Public ciphertext |

Mutation request headers are `X-HS-Artist-Key` (base64 raw Ed25519 public key), `X-HS-Timestamp` (Unix seconds), `X-HS-Nonce` (32 lowercase random hex characters), `X-HS-Body-SHA256` (lowercase hex), and `X-HS-Signature` (base64 Ed25519 signature). Signature payload is UTF-8:

```text
holochain-storage/http-auth/v1
<METHOD>
<exact URL path without query>
<Unix seconds>
<nonce>
<body SHA-256>
```

The node pins one allowed artist key (`--artist-key`) for this first version. Mutations require signatures from that key; every accepted manifest must be signed by the same key. The current per-process nonce cache and ±300-second clock window reject exact request replays **only during one process lifetime**. That is insufficient for adversarial internet deployment and must become restart-durable or be replaced by a stronger session protocol.

## Persistence and signing

- Encrypted objects: `<root>/objects/sha256/aa/<64-hex-ciphertext-hash>`.
- Public metadata: `<root>/packages/<64-hex-package-id>/manifest.json` (staged) and `receipt.json` (committed).
- Node Ed25519 secret: `<root>/node.ed25519`, created once and reused after restart (0600 on Unix). **Back this up** securely; if it is lost or leaked, identity continuity breaks.
- Root is forced to mode 0700 on Unix. Runs should use a dedicated unprivileged user, a private local filesystem, and a single process per root.
- Writes stage and fsync files, then rename and sync their containing directories. The prototype does not offer a complete multi-file transaction journal or solve all filesystem races.
- A package becomes publicly downloadable only after all encrypted chunks have been checked and a signed receipt committed.
- Existing committed objects remain available when the process restarts. Identical manifest initialisation and repeated commit calls are idempotent.

## Local cross-language integration tests

```bash
cargo test --manifest-path crates/storage-node/Cargo.toml
cargo build --manifest-path crates/storage-node/Cargo.toml
HOLOCHAIN_STORAGE_NODE_BIN=crates/storage-node/target/debug/holochain-storage-node \
  python -m unittest discover -s tests -p test_network_service.py -v
```

The tests spawn a real Rust TCP server, construct S1 Python ciphertext packages, verify S1 receipt signatures, detect a wrong artist and corrupted uploads, check missing chunks, preserve the node signing key across restart, and reconstruct original bytes. GitHub Actions runs these tests on a clean Linux runner.

## Cross-machine development without plaintext internet HTTP

Bind the Rust node to `127.0.0.1` on the **storage host**. Forward port 4780 over SSH from the artist machine:

```bash
ssh -N -L 4780:127.0.0.1:4780 storage-host
```

Then point the Python client at `http://127.0.0.1:4780` locally. SSH protects transport. **Do not use `--allow-insecure-remote-http` outside isolated test networks.** Node identity is authenticated out of band using a pinned node Ed25519 key and signed receipt; this first version does not provide server TLS certificates.

## Explicit limitations and security backlog

1. **No Holochain conductor integration yet.** The allowed artist key and expected node key are currently configured out of band. S2's key-binding/replica-claim records can replace that manual trust after real-conductor validation.
2. **No TLS listener, mTLS, or production access grants.** Only artist-authenticated upload, public encrypted downloads with end-to-end signature/hash validation. Do not publish the HTTP endpoint to the internet.
3. **No payment, streaming licence or listener authorisation.** Public ciphertext is not plaintext, but package metadata (and traffic timing) are visible. General-purpose storage will need visibility/access rules.
4. **No formal storage proof.** The receipt only attests to completed chunk verification at commit time. S3 challenge/audit protocol has a separate draft PR and will be wired into a running endpoint in a later slice.
5. **No durable challenge/replay ledger, rate limiting, request quotas, disk quota or concurrent per-package locks.** Server uses a single synchronous write lock and in-memory replay nonce cache. Do not expose to arbitrary tenants.
6. **No independent security review, fuzzing, Holochain discovery or on-demand MoQ delivery.** The HTTP transport is a constrained bootstrap for end-to-end testing, not a second long-term realtime media transport.
7. **Content keys must be securely backed up** by the artist/buyer. They are never stored in the node's data root or receipt. Perpetual buyer grants are separate from proof of a verified purchase.
8. **No continuous streaming transfer or range retry strategy yet.** Each chunk is a bounded in-memory request. This design's chunk addressing will later map to reliable on-demand MoQ requests.

## Integration strategy

S4 is based on **main/S1**, not the unmerged S2/S3 branches. Merge and validate S2, then add a Holochain-backed artist/node identity adapter. Merge and validate S3, then expose its challenges through authenticated node endpoints. Keep generic chunk packaging untouched and move network transfer to MoQ/QUIC when reliable seekable fetch is proven.

Links: [S2 PR #5](https://github.com/ConorTttttt/holochain-music/pull/5), [S3 PR #6](https://github.com/ConorTttttt/holochain-music/pull/6).
