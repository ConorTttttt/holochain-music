# S13 — Adaptive PCM buffering under verified MoQ/QUIC jitter (draft)

## What S13 changes

The last stage, S12, proved PCM output begins **before the encrypted file
transfer completes**: a real three-conductor Ubuntu run produced the first
PCM after 5 of 32 verified ciphertext objects, ~4,094 ms before the final
object; the strict Sweettest passed in 114.89 seconds.

S13 adds an **opt-in adaptive buffering policy** for that same authenticated
stream path. It is deliberately a finite-file, local-host prototype, not
live broadcasting, FEC, network repair, congestion control or production QoS.

- New `music_catalogue.adaptive_playback.AdaptivePcmPlayer` reuses S11's
  16 × 4KiB PCM slots (64KiB maximum) and S10's checked AES-GCM decryptor.
  It prebuffers 3 slots initially, raises the required refill target by 3
  slots after queue starvation (up to 12 slots), then decreases it by 1
  after 24 consecutive output blocks without starvation.
- A starvation event **stops feeding the device** while waiting for the
  next authenticated PCM block(s). This is a playback interruption, not
  invented silence, concealment, unauthorised decryption or loss repair.
  ALSA may separately underrun or buffer sound in hardware.
- Outcome fields include `rebuffer_events`, `rebuffer_duration_ms`,
  `adaptive_initial_blocks`, `adaptive_final_target_blocks`,
  `adaptive_ceiling_blocks`, `startup_delay_ms`, `max_inter_output_ms`,
  `buffer_underruns`, the 64KiB high-water mark, authenticated PCM SHA-256
  and frame count. There is no guarantee of smooth playback when average
  ciphertext delivery is slower than the PCM consumption rate.
- Rust MoQ publisher gains test-only flags `--jitter-every` and
  `--jitter-delay-ms`. Both default to 0 (no change to existing S8–S12).
  For the integration fixture, base delay is 60ms/object plus an extra
  450ms after every sixth object. This simulates periodic delay **over real
  QUIC**; it does not simulate packet loss or verify an external network.
- No S2/S5 DNA changes, host-side content keys, or changes to the S10 grant.
  S9 still authenticates both DNA pins, Holochain author, signed file
  commitment/receipt and TLS fingerprint; S10 still requires owner-signed
  X25519 listener grant. Each S1 chunk must be SHA-256-checked and its
  AES-GCM tag verified before PCM enters the queue.

## Ubuntu validation

Keep the previously working S9 DNA. Keep your lockfiles and build caches.

```bash
cd /mnt/holochain/holochain-music
git status
git fetch origin
git switch --track origin/feat/s13-adaptive-moq-jitter
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_s13_adaptive_playback.py -v

mkdir -p /mnt/holochain/tmp
export TMPDIR=/mnt/holochain/tmp CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cargo test --manifest-path crates/moq-music/Cargo.toml
cargo build --manifest-path crates/moq-music/Cargo.toml
export MUSIC_STORAGE_DNA=/mnt/holochain/tmp/music_storage_s9_1793906946.dna
export HOLOCHAIN_MUSIC_PYTHON="$PWD/.venv/bin/python"
export HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node"
export HOLOCHAIN_MOQ_BIN="$PWD/crates/moq-music/target/debug/holochain-music-moq"
ls -lh "$MUSIC_STORAGE_DNA" "$HOLOCHAIN_STORAGE_NODE_BIN" "$HOLOCHAIN_MOQ_BIN"

nix develop ./music-e2e --command bash -euc '
  cd /mnt/holochain/holochain-music/music-e2e
  cargo test --test s13_adaptive_moq_playback_sweettest -- --nocapture
'
```

Target (unverified until executed):

```text
test bob_adapts_pcm_buffer_under_real_moq_jitter ... ok
test result: ok. 1 passed; 0 failed
```

The Rust test uses three independent **actual Holochain 0.7 conductors**,
real S4 HTTP storage, authenticated Holochain-authored endpoint and genuine
MoQT/QUIC, AES-GCM grants, and a 4-second WAV file. Output defaults to a
paced silent PCM sink for CI. It must produce authenticated PCM before the
last verified ciphertext object, verify every object and every PCM frame,
report buffer statistics and never exceed 64KiB. This is different from a
unit test that mocks the conductor callback; neither one substitutes for the
other.

Optional ALSA speaker output uses the same test but **requires a working
Linux speaker device**, user opt-in, and comfortable volume:

```bash
export HOLOCHAIN_S13_AUDIO_BACKEND=alsa
nix develop ./music-e2e --command bash -euc '
  cd /mnt/holochain/holochain-music/music-e2e
  cargo test --test s13_adaptive_moq_playback_sweettest -- --nocapture
'
unset HOLOCHAIN_S13_AUDIO_BACKEND
```

## Acceptance criteria and honest limitations

- Exact artist-signed manifest, S2 Holochain author, S4 receipt, host MoQ
  endpoint and TLS pin, S10 listener grant, S1 ciphertext hash and AES-GCM
  verification. Corrupt/missing chunks always fail closed; no decoded
  audio is attributed to a complete transfer after a failure.
- First PCM strictly precedes the last verified MoQ chunk, including the
  measured time gap and chunk-count evidence. No false positive due to an
  absent JSON field or non-atomic progress observation.
- Correct output PCM SHA-256, frame count and bounded queue even under
  periodic delay; rebuffer events and duration measured. Under sustained
  network deficit, some buffering interruptions are unavoidable; this is
  *not* a guarantee of zero dropouts. No seek, rewind, replay, relay/NAT,
  multi-host availability or packet-loss repair.
- The signed grant proves local key access, not payment, licence entitlement,
  copy protection, artist rights or revocation. This prototype is not a
  streaming service suitable for public deployment.
