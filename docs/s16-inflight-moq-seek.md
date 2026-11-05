# S16 — Owner-granted WAV seeking while encrypted MoQ arrives (DRAFT)

**Stack:** [S15 PR #19](https://github.com/ConorTttttt/holochain-music/pull/19) → S16. No DNA, Holochain catalogue schema, S1 manifest, S10 signed-grant or S4 node changes. No changes to default S9–S15 streaming behavior.

## Scope

Previously S14/S15's `VerifiedWavSeeker` required the full encrypted CAS before seeking. S16's opt-in `InflightWavSeeker` enables a *preselected* series of frame-exact WAV PCM16 seek windows **during** a genuine S9 Holochain-discovered, TLS-fingerprint-pinned and owner-granted MoQ/QUIC download:

1. Bob verifies Alice's Ed25519-signed S1 manifest and per-listener X25519 owner grant **before** connecting to MoQ or opening a sound device.
2. S9's existing progress events fire only after each received ciphertext object was checked against its manifest SHA-256 and atomically installed in the listener CAS.
3. S16 waits for the exact required chunk index. This uses S12's monotonic `VerifiedChunkGate`: missing earlier chunks and a failed transfer cannot be silently skipped.
4. Before opening ALSA/null output, S16 authenticates the full canonical RIFF/WAVE PCM16 header and verifies its exact signed total-byte/frame layout.
5. At each seek, S16 uses manifest-backed plain byte offsets, decrypts *only relevant* AES-GCM authenticated chunks, and outputs frame-aligned PCM blocks via S11's maximum 64 KiB bounded queue. It can rewind into earlier verified objects while later ones are arriving.
6. The S9 download must finish and the complete signed ciphertext CAS be reverified before the result reports overall success. A failed transfer cannot be reported as a completed song, even if some earlier authenticated PCM was already played.

**This is NOT MoQ random-access range prioritisation.** The publisher still delivers ciphertext sequentially. Seeking ahead of the download point must wait until those chunks arrive; a seek into received ciphertext can start promptly. This first integration slice exercises a fixed two-range plan, **not** arbitrary interactive seek commands from a desktop UI. The exact comparison test uses a 4-second, 16 kHz mono synthetic WAV with seeks to frame 24,007 and backward to frame 7,001 (4,096 frames each), and confirms that the first output of **both** occurs before the last encrypted MoQ object.

## Verification: local authoring

- New Python tests: `python -m unittest discover -s tests -p test_s16_inflight_seek.py -v` — **13 passed** in the authoring environment.
- Full Python regression: **166 run, 160 passed, 6 expected skips, 0 failures**.
- The authoring environment cannot compile or launch native Holochain/QUIC. The real Sweettest remains **unverified until executed on Ubuntu or CI**.

## Ubuntu verification (after existing S15 run finishes)

Preserve existing Cargo target directories, lockfiles and compiled DNAs; S16 adds no MoQ executable or DNA changes relative to S15.

```bash
cd /mnt/holochain/holochain-music
git status
git fetch origin
git switch --track origin/feat/s16-inflight-granted-seek
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_s16_inflight_seek.py -v

mkdir -p /mnt/holochain/tmp
export TMPDIR=/mnt/holochain/tmp CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
export MUSIC_STORAGE_DNA=/mnt/holochain/tmp/music_storage_s9_1793906946.dna
export HOLOCHAIN_MUSIC_PYTHON="$PWD/.venv/bin/python"
export HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node"
export HOLOCHAIN_MOQ_BIN="$PWD/crates/moq-music/target/debug/holochain-music-moq"

nix develop ./music-e2e --command bash -euc '
  cd /mnt/holochain/holochain-music/music-e2e
  cargo test --test s16_inflight_moq_seek_sweettest -- --nocapture
'
```

Target (not yet observed):

```
test bob_seeks_forward_and_backward_before_final_verified_moq_chunk ... ok
test result: ok. 1 passed; 0 failed
```

Optional physical output after the silent run succeeds:

```bash
export HOLOCHAIN_S16_AUDIO_BACKEND=alsa
nix develop ./music-e2e --command bash -euc '
  cd /mnt/holochain/holochain-music/music-e2e
  cargo test --test s16_inflight_moq_seek_sweettest -- --nocapture
'
unset HOLOCHAIN_S16_AUDIO_BACKEND
```

At comfortable volume, two short tone excerpts may be audible with a gap while the seek waits for its encrypted bytes. The fixture is generated, *not* a paid song.

## Security and limitations

- The S10 licence-grant issuer still needs an independently authenticated Bob X25519 key binding and purchase/rights enforcement; this code does **not** implement payments or owner key rotation/revocation.
- PCM buffers only inside Bob's authorised listener process. No plaintext music or content keys are sent to Holochain, Carol's S4 storage node or MoQ.
- A failed/tampered ciphertext chunk can stop the range and abort the overall result. Previously played authenticated PCM cannot be unplayed; no fabricated audio or unverified chunk substitution occurs.
- No priority-ordered QUIC/MoQ range requests, live seek cancellation/switching, variable-rate codec decoding, gapless switching, HTTP fallback, public-network NAT traversal, cross-machine deployment, or production availability guarantees. These are future milestones.
- Not a claim of physically audible S16 playback or real-conductor completion until the corresponding Ubuntu test passes.
