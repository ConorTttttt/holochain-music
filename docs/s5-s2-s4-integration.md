# S5 → S2 → S1 → S4: signed catalogue retrieval (integration draft)

**Status:** review/test integration branch, not a production music player. The
legacy Python client and Holochain zome networks are not yet connected through
a live, authenticated conductor WebSocket bridge; this limitation is essential.

## Trust and data flow

1. Artist publishes catalogue metadata in the S5 `music_catalogue` DNA.
2. The *same agent* publishes an S2 `SigningKeyBinding` with purpose
   `owner-manifest` and `FileCommitment` in the storage identity DNA.
3. Storage node publishes its own S2 `host-receipt` key binding and
   `ReplicaClaim`; its Ed25519-signed S4 receipt acknowledges accepted bytes.
4. A **trusted, validated** conductor returns the Holochain action authors,
   action hashes and bodies. Never treat arbitrary JSON as that proof.
5. `music_catalogue.verified_retrieval.fetch_verified_track` checks that
   catalogue author, agent key, S1 signed manifest, owner commitment, signed
   receipt, and host receipt claim all refer to the *same exact file*.
6. A new `ReadOnlyStorageNodeClient` downloads S4 ciphertext, validates the
   pinned signed manifest, signed node receipt and every ciphertext hash.
   **No artist signing private key, content key or plaintext goes to the node.**
7. Playback, key grants, verified payment and MoQ seekable fetch are not part of
   this integration stage.

Note: A signed receipt is not proof of *continued* custody. DHT key bindings
are currently append-only; selecting a key among multiple bindings requires
an explicit policy, and the caller must not accept first-seen keys blindly.

## Run on Ubuntu / Holonix

From `/mnt/holochain/holochain-music` on the integration branch:

```bash
# Python contracts; the separate node test skips if Rust binary is not present
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_verified_catalogue_download.py -v

# Real Rust node + listener-side verified ciphertext retrieval
cargo build --manifest-path crates/storage-node/Cargo.toml
HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node" \
  python -m unittest discover -s tests -p test_verified_catalogue_download.py -v

# Real Holochain 0.7 identities in *both* DNAs on Alice/Bob conductors
# Use Holonix 0.7; from repository root:
nix develop ./music-e2e
cd music-dna
cargo build --release --target wasm32-unknown-unknown
hc dna pack workdir
cd ../dna
cargo build --release --target wasm32-unknown-unknown
hc dna pack workdir
cd ../music-e2e
cargo test --test catalogue_storage_identity_sweettest -- --nocapture
```

For your constrained filesystems, in the same Holonix terminal before building:

```bash
mkdir -p /mnt/holochain/tmp
export TMPDIR=/mnt/holochain/tmp
export CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0
```

A fresh combined conductor build can be several GB; do not delete Cargo targets
unless you need to reclaim space. Run `df -h /mnt/holochain /tmp /` first.

## What tests do and do not establish

- Python unit tests exercise signatures, manifest hashes, agent/key/receipt
  mismatch, and reject altered records **before any ciphertext download**.
- With `HOLOCHAIN_STORAGE_NODE_BIN`, one integration test runs the actual S4
  HTTP node and proves a listener retrieves authenticated encrypted bytes
  without possessing the artist's private signing key. It reconstructs the
  original in the test *only because the fixture also holds the content key*.
- Rust Sweettest runs two real Holochain conductors, installs S2 and S5 under
  one shared agent identity per conductor, waits for gossip, verifies Bob's
  discovered record authors/commitments, and rejects forged S2 authorship.
- These suites are separate: a production-ready, conductor-authenticated
  Python adapter is still required to join them without hand-built fixtures.
- A host claim can be signed by a node, but does not prove the artist selected
  it or that the host remains online. Public S4 ciphertext is fetchable by any
  reader who knows the file ID; content keys remain out of band.
- S2 and S4 are still WIP PRs. This integration PR is stacked and not a
  substitute for reviewing or merging those independently.
