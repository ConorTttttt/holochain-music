# S9 draft — Holochain-authenticated MoQ endpoint discovery

## What this proves

This is an **experimental local-only** integration of Holochain Music S7 and
S8. The storage host posts an endpoint and SHA-256 TLS certificate fingerprint
under its own authenticated Holochain agent. Bob discovers the binding through
his pinned two-DNA Holochain 0.7 hApp, verifies the signed S1 manifest and
S4 receipt, and only then receives ciphertext over real MoQT draft-14/QUIC.

```
Alice ─ S5 track/file manifest SHA-256 ───┐
      └ S2 artist signing key/commitment ─┤
                                          │  Bob's trusted Holochain conductor
Host ─ S2 signed host receipt key ────────┤   (authenticated app WebSocket)
      └ S2 replica claim ────────────────┤
      └ S2 host-authored MoqEndpoint ────┘
              │ file_id + manifest digest + URL + cert SHA-256
              v
Bob's `music_catalogue.moq_conductor.receive_moq_from_live_conductor`
    ├ checks two DNA pins + action authors + unique commitments
    ├ retrieves S1 manifest and S4 receipt, verifies Ed25519 signatures
    ├ launches S8 receiver with ONLY Holochain-attested URL/TLS pin
    └ re-hashes every received ciphertext object against signed S1 manifest
              │
              v
Host's REAL MoQ/QUIC publisher → listener CAS (ciphertext only)
```

### New S2 DNA entry

`MoqEndpoint` is a public, append-only entry:

- `schema = holochain-storage/moq-endpoint/v1`
- `node_agent` **must** match Holochain action author
- `owner_agent`, `file_id`, `manifest_sha256` must match S5/S2 S1 commitments
- `url`: **only `https://127.0.0.1:PORT` in S9 prototype**
- `cert_fingerprint_hex`: 64 lowercase hex characters, SHA-256 of the
  publisher's TLS leaf certificate

New link: `AgentToMoqEndpoint`. New coordinator functions:
`publish_moq_endpoint(endpoint)` and `get_moq_endpoints(host_agent)`.
Validation is deterministic and on the *integrity* zome. The Rust client
rejects missing or multiple matching endpoints rather than guessing among
old keys/cert rotations. It never treats the readiness JSON as the listener's
trust source.

**DNA upgrade:** Adding an entry type/link type to the integrity zome **changes
the S2 DNA hash**. This is a *new network identity*, not a coordinator hot-swap.
Rebuild and pack `dna/workdir/music_storage.dna` and use newly pinned hashes;
existing old S2 networks do not magically migrate their entries or identities.
S7 and S8 draft branches remain unchanged.

## Ubuntu test instructions

Do not delete or `git clean` local lockfiles or build targets. Use the larger
`/mnt/holochain` filesystem for build/temp files:

```bash
cd /mnt/holochain/holochain-music
git status
git fetch origin
git switch --track origin/feat/s9-holochain-moq-endpoint

source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_s9_moq.py -v

export TMPDIR=/mnt/holochain/tmp
export CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0
# Reuse your working S4 storage-node binary.
cargo build --manifest-path crates/moq-music/Cargo.toml
export HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node"
export HOLOCHAIN_MOQ_BIN="$PWD/crates/moq-music/target/debug/holochain-music-moq"
export HOLOCHAIN_MUSIC_PYTHON="$PWD/.venv/bin/python"

nix develop ./music-e2e
# Repack storage DNA: its INTEGRITY WASM HAS CHANGED.
cd /mnt/holochain/holochain-music/dna
cargo build --release --target wasm32-unknown-unknown
hc dna pack workdir
# S5 DNA is unchanged, keep its packed bundle from S7.
cd /mnt/holochain/holochain-music
ls -lh music-dna/workdir/music_catalogue.dna dna/workdir/music_storage.dna
cd music-e2e
cargo test --test s9_holochain_moq_sweettest -- --nocapture
```

**Expected only after a successful run**: one test named
`bob_discovers_host_authored_moq_endpoint_and_receives_verified_quic` passes.
The test starts two Sweettest Holochain conductors, a real Rust S4 node, and a
real MoQ publisher/subscriber. The listener's Python helper is *not given*
the publisher readiness URL or certificate. It obtains them via the actual
Rust admin/app WebSocket bridge and checks every ciphertext chunk.

This new Rust Sweettest remains **unverified until CI or Ubuntu actually
compiles and runs it**. The 7 Python S9 trust-boundary unit tests are mocks of
subprocess inputs, not a replacement for the real-conductor test.

## Limitations and security review

- **Localhost only:** this endpoint cannot be used by peers on separate hosts;
  NAT traversal, public addresses, TLS+QUIC deployment and relays are future
  work. Never expose the conductor admin WebSocket remotely.
- **Host and listener share Bob's agent** in the 2-conductor fixture. A future
  3-agent or multi-machine acceptance test must separate Carol (host) from
  Bob (subscriber).
- **No rotation/revocation:** endpoint entries and indexes are append-only.
  Duplicate matching endpoints fail closed. Expiration, replacement and
  revocation policy must be designed before public release.
- **Host-authored claim** does not establish continued custody, nor does it
  prove that a public route remains reachable. A QUIC TLS match does prove
  possession of the certificate key corresponding to the *pinned* fingerprint.
- **No buyer authorisation or plaintext access:** MoQ serves encrypted chunks
  to any subscriber able to connect. Content keys remain local to the test.
  Real playback requires grants, buffering, seeking, codec and rights handling.
- **Finite ordered transport only:** one MoQ subgroup is used; S9 deliberately
  does NOT claim low-latency live player behaviour, retry or seeking.
- **No migration of S2 DHT:** changing integrity zome forks the DNA network.
  Existing production registrations would need an explicit migration plan.
