# S12 draft — playback while verified MoQ ciphertext is still arriving

S12 extends the **working S11** complete-file player without replacing its
trust model or modifying either DNA. It overlaps (1) the finite S8/S9 genuine
MoQ/QUIC ciphertext transfer, (2) per-chunk S1 AES-GCM authenticated decryption,
and (3) S11's bounded, clocked WAV PCM sink. **S12 is not a live broadcast
system, FLAC/Opus decoder, or public/seekable/adaptive player.**

## Trust and transport design

1. Bob uses the same trusted local **S9 Holochain conductor**: installed app,
   pinned S5/S2 DNA hashes, authenticated author identities, artist Ed25519 key,
   S1 signed manifest digest, Carol's receipt/replica claim and host-authored
   QUIC URL/TLS certificate fingerprint. The publisher readiness file is NOT
   supplied to the listener.
2. Bob verifies Alice's short-lived, recipient-specific signed **S10 grant**
   and X25519-wrapped key using the **S2-attested artist key and Bob's actual
   Holochain agent** *before opening MoQ or ALSA*. The issuer must still
   authenticate Bob's X25519 key and establish rights independently.
3. Opt-in Rust `holochain-music-moq receive --progress-jsonl` emits a bounded
   JSON event **only after SHA-256 and exact-size verification and atomic CAS
   persistence of each MoQ object**, then a `transfer_complete` summary.
   The legacy one-shot `receive` command output remains unchanged.
4. Python parses the ordered progress events with deadlines/size limits and
   re-hashes the exact **S1 manifest-pinned CAS object**, before signalling its
   release. An event claiming a chunk that is absent, corrupt, duplicated, or
   out of order cannot unblock playback. Transfer termination without all
   objects and final success fails closed.
5. S10's forward-only WAV reader may now **wait for each verified object**.
   It authenticates the AES-GCM tag/AAD of each chunk before any corresponding
   PCM leaves the listener. WAV metadata is validated before opening ALSA.
   It never writes a plaintext WAV. Previous S10/S11 calls without a waiter
   still demand the entire verified CAS *before* output.
6. S11's 64 KiB FIFO, 4 KiB blocks, backpressure, pause/resume/stop, local
   pacing and optional `aplay` remain intact. Network stalls do **not** get
   treated as silence or skipped audio; a missing chunk aborts playback.

The `stream_granted_moq_from_live_conductor` report includes
`first_pcm_before_last_chunk`: true means the **first output write occurred
before the last independently verified MoQ chunk became available**, not just
before the QUIC session closed. A last-chunk timestamp is recorded when its
CAS hash is validated. The test deliberately spaces objects apart with the
publisher's **test-only** `--chunk-delay-ms 150`. For normal publishing the
existing 2ms default remains. S12 still requires the transfer's full verified
completion *and* a matching final PCM SHA-256/frame-count before claiming
`playback_complete=true`.

## Three-agent Ubuntu test

Use the already-verified S9 DNA, S4 node and S11 code. **No new DNA** is
required. S12 modifies the native Rust MoQ executable; **rebuild that workspace
before the real test**. Do not delete existing Cargo caches, lockfiles or DNA
bundles. From the repository root:

```bash
cd /mnt/holochain/holochain-music
git status
git fetch origin
git switch --track origin/feat/s12-moq-playback-overlap
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_s12_streaming_playback.py -v

mkdir -p /mnt/holochain/tmp
export TMPDIR=/mnt/holochain/tmp CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
export MUSIC_STORAGE_DNA=/mnt/holochain/tmp/music_storage_s9_1793906946.dna
export HOLOCHAIN_MUSIC_PYTHON="$PWD/.venv/bin/python"
export HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node"
export HOLOCHAIN_MOQ_BIN="$PWD/crates/moq-music/target/debug/holochain-music-moq"

cargo test --manifest-path crates/moq-music/Cargo.toml
cargo build --manifest-path crates/moq-music/Cargo.toml
ls -lh "$MUSIC_STORAGE_DNA" "$HOLOCHAIN_STORAGE_NODE_BIN" "$HOLOCHAIN_MOQ_BIN"

nix develop ./music-e2e --command bash -euc '
  cd /mnt/holochain/holochain-music/music-e2e
  cargo test --test s12_overlapping_moq_playback_sweettest -- --nocapture
'
```

**Expected only after actual Ubuntu/CI verification:** one test
`bob_plays_granted_pcm_before_last_moq_chunk_arrives` passes. It installs
**three distinct actual Holochain conductors** (Alice, Bob, Carol), uploads a
valid **4-second WAV** into the real S4 node, publishes Carol's MoQ endpoint,
issues Alice's X25519-encrypted signed key grant to Bob, starts genuine MoQ,
verifies **the first PCM output precedes the last verified ciphertext chunk**,
and verifies the final PCM SHA-256 and frame count. The sink is timed **null**,
so CI requires no speakers. S11 already verified the same player with real
ALSA speakers on the HP Pro Mini; S12's overlapped **hardware** playback is
not yet separately verified.

## Boundaries and failure handling

- The published endpoint is **localhost only**, tied to the host's pinned
  certificate and Holochain record. This is not WAN/NAT/relay deployment.
- This remains **an ordered finite MoQ subgroup**, not adaptive low-latency
  media. There is no repair, retry/resume, random access/seek, multi-listener
  admission or speculative decryption. Dropped chunks fail closed.
- A listener may hear authenticated *earlier* PCM before a later network error
  is detected. Final failure is still reported and the sound device is
  stopped. Previously heard samples cannot be revoked or "unplayed".
- WAV PCM16, mono/stereo and S10's existing sample rates only; no FLAC/Opus.
  The 64 KiB PCM queue remains bounded, but decryption of one AES-GCM S1 chunk
  can consume up to the existing 4 MiB plaintext chunk limit in RAM.
- Contents of the S10 signed key grant, grant issuer's rights decision and
  agent-to-X25519 binding are independent of MoQ. Neither secret key, plaintext
  nor playback grant is published to S2/S5/S4/MoQ. Python process memory does
  hold the unwrapped key while playing and is not a hardened keystore.
