# S11 draft — bounded timed WAV/PCM playout and optional Linux speakers

## What S11 adds to S10

The **S9 Holochain/QUIC ciphertext download** remains a finite, complete transfer.
Afterwards, S10 validates the S1 Ed25519 manifest, the artist's authenticated
S2 signer key, Bob's X25519 owner-signed grant, and the S1 AES-GCM ciphertext.
**Only then** can S11 open a local PCM device and begin audio output.

- `music_catalogue/buffered_playback.py` — a **16-slot, 4KiB-slot** FIFO
  (maximum **64 KiB queued plaintext**) with backpressure. Supported format
  matches S10: WAV PCM16, mono/stereo, 8–48 kHz common rates.
- A worker uses local monotonic timing to pace PCM to the playback sink. It
  prebuffers three blocks; queue starvation increments `buffer_underruns`
  rather than silently dropping frames.
- Separate-thread `pause`, `resume`, `stop`: pause preserves authenticated PCM
  already queued; resume continues; stop aborts the device and discards the
  queued buffers. Pause is **block-boundary** (and hardware may have its own
  additional latency). No seek or fine-grained hardware latency correction.
- **ALSA output:** calls the system `aplay` command directly with explicit
  `-t raw -f S16_LE -r RATE -c CHANNELS -D DEVICE`. PCM is piped through
  stdin; no plaintext WAV/PCM file is written. If `aplay` is missing, the
  selected device is invalid or the process fails, playout fails closed.
  It does not auto-install packages, change volume or access microphones.
- **Null output:** uses the *same* timed queue but hashes/discards PCM in
  memory. Test and CI never require actual audio hardware. The source PCM
  digest, frame count and output PCM digest must match exactly.
- Optional `format_callback` in S10's `play_granted_wav` opens a backend only
  **after grant, manifest, ciphertext, and WAV header validation**, keeping
  the original S10 API unchanged for callers that omit the callback.

**This is locally clocked audio after download, not overlapping MoQ delivery
with audio playback.** Buffering, seeking, packet repair, real network
jitter handling, playlist/FLAC codecs, commercial entitlement checks and
revocation are future tasks. The S10 grant issuer must still authenticate
Bob's X25519 key ownership and enforce purchase/licensing policy outside this
prototype. Local memory holds the unwrapped AES key while decrypting.

## Automated Ubuntu verification (no speakers required)

S11 adds **no DNA changes**. Reuse the exact S9 storage DNA that passed S9
and S10. Don't delete Cargo caches, local lockfiles or packed DNAs.

```bash
cd /mnt/holochain/holochain-music
git status
git fetch origin
git switch --track origin/feat/s11-buffered-alsa-playback

source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_s11_buffered_playback.py -v

mkdir -p /mnt/holochain/tmp
export TMPDIR=/mnt/holochain/tmp CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
export MUSIC_STORAGE_DNA=/mnt/holochain/tmp/music_storage_s9_1793906946.dna
export HOLOCHAIN_MUSIC_PYTHON="$PWD/.venv/bin/python"
export HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node"
export HOLOCHAIN_MOQ_BIN="$PWD/crates/moq-music/target/debug/holochain-music-moq"
ls -lh "$MUSIC_STORAGE_DNA" "$HOLOCHAIN_STORAGE_NODE_BIN" "$HOLOCHAIN_MOQ_BIN"

nix develop ./music-e2e --command bash -euc '
  cd /mnt/holochain/holochain-music/music-e2e
  cargo test --test s11_buffered_granted_moq_sweettest -- --nocapture
'
```

**Expected only if the live run succeeds:**

```
test bob_discovers_moq_and_plays_granted_wav_on_timed_pcm_buffer ... ok
test result: ok. 1 passed; 0 failed
```

That test uses **three actual Holochain conductors** (Alice, Bob, Carol),
the real S4 Rust node, real MoQT/QUIC and S10's owner-signed grant, then feeds
WAV PCM through the timed bounded queue into a *silent* null backend. It
checks all PCM frames/hashes and the 64KiB upper bound. The original S10
test remains unchanged and continues to test the unpaced hash sink.

## Optional local HP Pro Mini audible speaker test

This is a separate **manual** test and will generate a quiet **440 Hz sine
tone** (initially three seconds) with an ephemeral owner-signed test grant.
It does not fetch S9 music or establish real buyer rights; it only verifies
the grant/decrypt/buffer/ALSA output path and whether your own speaker works.
Use a sensible speaker volume before running, and do not use headphones at a
high volume.

```bash
cd /mnt/holochain/holochain-music
source .venv/bin/activate
command -v aplay || echo 'Missing aplay: install Ubuntu alsa-utils to use speakers'
aplay -l  # list ALSA devices, if available

# No audio device: same demo with real pacing and a silent output device.
python -m music_catalogue.playback_cli demo --backend null --seconds 3

# Audible audio, using your default output device; optional pause/resume/stop:
python -m music_catalogue.playback_cli demo --backend alsa --device default --seconds 8 --controls
```

Controls: type `p` then Enter to pause, `r` then Enter to resume, `s` then
Enter to stop. When successful, the command prints `"playback_complete":
true` and the two PCM hashes match. If the device fails or stops early, it
must exit with an error, **not** claim a completed transfer. Devices may
require a different ALSA name, or running under a desktop user session with
PipeWire/PulseAudio configured. Do not run the audio demo as root.

For a locally installed *actual* owner-signed S10 grant/manifest/ciphertext,
advanced developers can use `python -m music_catalogue.playback_cli play
--help`. The `--trusted-artist-hex` and `--listener-agent` inputs must come
from the authenticated S9/S10 local conductor and key-binding checks; taking
them from a peer or the grant itself would defeat the security boundary.
There is no production keystore UI yet; the CLI `--recipient-private-file`
reads a private local 32-byte X25519 key, which must never be shared.

## What is still unverified

The authoring environment has no speaker device or compiled Holochain
conductor. Passing Python tests proves buffering/control behaviour and grant
boundary, **not** audible sound or live-conductor integration. Those require
the Ubuntu tests above. ALSA hardware may add output latency beyond the
bounded application queue. The S11 Sweettest currently uses the null sink,
so only the optional manual test can confirm actual sound through speakers.
