# S7 (draft) — one real Holochain-to-encrypted-download integration test

**Status:** source implementation + Python fixture tests; **full S7 Rust
Sweettest requires Ubuntu/Holonix or CI verification**. Do not confuse
individual S4/S6 successes with the as-yet-unverified combined test.

## What is exercised, in one test

`music-e2e/tests/s7_live_verified_retrieval_sweettest.rs` coordinates:

1. Python's *real* S1 `create_package` produces a signed, AES-256-GCM
   chunked package of **synthetic opaque audio test data**. Artist Ed25519
   secret and AES content key are written to a private temporary workspace.
2. A real S4 `holochain-storage-node` Rust HTTP service starts on
   `127.0.0.1` with *only the artist public key*. The Python artist client
   uploads and commits the encrypted chunks; it verifies the real node receipt.
3. Two Holochain 0.7 Sweettest conductors start with **both S5 catalogue and
   S2 storage identity DNAs**, sharing one agent identity per conductor.
   Alice publishes the actual S1 manifest digest, artist public signing-key
   binding, track and file commitment. Bob publishes the actual node receipt
   signing-key binding and replica claim, under his own Holochain agent.
4. After `await_consistency_s` on **both** DNAs, a **separate Python process**
   invokes `fetch_from_live_conductor`, which in turn starts the production
   **Rust authenticated admin/app WebSocket bridge**, pinned to Bob's app ID,
   two DNA hashes and own agent. No `AuthoredRecord` or signed-manifest test
   objects are supplied to this read path.
5. The listener fetches the S4 signed manifest by ID, verifies it against
   the published S5/S2 commitment and Ed25519 artist key, validates the real
   node receipt and Bob's S2 replica claim, and downloads encrypted chunks.
6. The test harness alone uses its local AES content key to decrypt the
   downloaded ciphertext and assert a byte-for-byte SHA-256 match with the
   source. This is a test assertion, **not an implemented buyer key grant**.

There is no mock Holochain response, fake receipt or simulated storage-node
payload in the complete S7 path. All services run locally in one test process
with child processes and private temporary directories; they are cleaned up.

## Ubuntu commands

From the project root on `feat/s7-live-verified-retrieval`:

```bash
cd /mnt/holochain/holochain-music
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_s7_fixture.py -v

# Build the actual S4 node if not already compiled:
cargo build --manifest-path crates/storage-node/Cargo.toml

# Holonix main-0.7 (same as S6); use existing packed music/storage DNA files.
nix develop ./music-e2e
mkdir -p /mnt/holochain/tmp
export TMPDIR=/mnt/holochain/tmp
export CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0
export HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node"
export HOLOCHAIN_MUSIC_PYTHON="$PWD/.venv/bin/python"
ls -l music-dna/workdir/music_catalogue.dna dna/workdir/music_storage.dna
cd music-e2e
cargo test --test s7_live_verified_retrieval_sweettest -- --nocapture
```

If one of the `.dna` bundles is missing, rebuild/pack as in
`docs/s5-s2-s4-integration.md`; do not delete previous Cargo targets to
rebuild from scratch unnecessarily. Keep the node binary on `/mnt/holochain`
(there was very little free space on `/` in earlier Ubuntu checks).

## CI

The `real-conductors` job in
`.github/workflows/music-catalogue-storage-integration.yml` now provisions
Python and the S4 executable before entering Holonix, then runs S6 and S7
real-conductor tests. The ordinary Python workflow also runs the fixture tests.

## Security and limitations

- The Holochain admin WebSocket is privileged and must stay on localhost.
  Signed Holochain action authorship is asserted by the **local validating
  conductor** and pinned DNAs, not by independently verifiable JSON output.
- All artist/content key material is test-only in a temporary 0700 directory;
  private keys never go into Holochain, the Rust node, or bridge arguments.
- An S4 receipt and an S2 host claim are **not proof of ongoing custody**.
  Signed keys are append-only without production rotation/revocation policy.
- This proves **encrypted download** only, not decoding/playing real audio,
  buyer entitlement, content-key delivery, licensed rights or MoQ/QUIC media.
- It exercises two **local** conductors and a local HTTP node, not a deployed
  internet-facing network. Do not expose plaintext HTTP S4 to public clients.
- The fixture uses the listener Bob as the hosting agent too to keep this
  two-conductor E2E test small; a separate external host identity and receipt
  publication workflow is still a deployment requirement.
