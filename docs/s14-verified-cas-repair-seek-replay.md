# S14 — Pinned S4 ciphertext repair and authorised seek/replay

**Draft, stacked on S13 / PR #17.** This is an opt-in listener-side feature.
S1/S2/S5 DNA schemas, artist-signed manifests, S10 owner-signed content grants,
S13 adaptive streaming, and the primary MoQ/QUIC path are unchanged.

## Scope and security boundary

The real S14 integration first repeats S13's actual three-conductor Holochain,
S4 encrypted storage node, authenticated MoQ/QUIC endpoint, listener-specific
signed content grant, chunk-by-chunk AES-GCM verification and jittered streaming
playback. It then **deletes exactly one ciphertext object from Bob's local CAS**
and asks Carol's existing S4 node to provide the missing ciphertext object.

The S4 repair client is explicitly constructed by the trusted local caller
with the S9 bridge's <b>verified public artist signing key</b>, <b>verified public
host receipt key</b>, and S5/S2-pinned exact signed-manifest SHA-256. It
refuses a mismatched manifest, invalid host receipt, corrupted object, local
symlink, any already-corrupt local object or excessive repair budget. A
replacement is verified against the signed S1 object digest before atomic
no-overwrite installation. Final full-CAS verification must succeed. **S4
never sees Alice's key or Bob's X25519 private key.** No plaintext music file
is reconstructed during repair.

Following successful repair, Bob opens a `VerifiedWavSeeker`. Construction
verifies the entire CAS and the artist-signed listener grant, and authenticates
the canonical WAV PCM16 frames. A seek maps an exact audio frame range back
to encrypted S1 chunks, rechecks their SHA-256 and AES-GCM authentication,
then emits frame-aligned PCM in <=16 KiB blocks to S11's bounded clocked
`null` or opt-in ALSA output. Replay is a second authenticated, separately
clocked read of the same range, with the exact expected PCM SHA-256.

**Limitations:** This is missing-*local*-CAS repair via pinned S4 HTTP, not
QUIC packet-loss recovery or MoQ indexed-range retransmission, not seeking
while arbitrary future MoQ chunks are still being received, and not public
multi-host deployment. Corrupt local data fails closed rather than being
silently replaced. Host availability is not guaranteed by a signed receipt.
Only uncompressed canonical PCM16 WAV is seekable. Audio may enter memory in
plaintext in Bob's authorised process, but not the DHT, S4 or MoQ. Payment,
commercial entitlement, license revocation, cross-machine discovery and
sound-card latency remain separate concerns.

## Ubuntu verification

S14 changes only Python, the Sweettest and CI — **no new DNA or Rust MoQ build**.
Retain the S9 packed storage DNA and existing S13 MoQ/S4 executables.

```bash
cd /mnt/holochain/holochain-music
git status
git fetch origin
git switch --track origin/feat/s14-verified-cas-repair-seek
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_s14_seek_repair.py -v

mkdir -p /mnt/holochain/tmp
export TMPDIR=/mnt/holochain/tmp
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
export MUSIC_STORAGE_DNA=/mnt/holochain/tmp/music_storage_s9_1793906946.dna
export HOLOCHAIN_MUSIC_PYTHON="$PWD/.venv/bin/python"
export HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node"
export HOLOCHAIN_MOQ_BIN="$PWD/crates/moq-music/target/debug/holochain-music-moq"

nix develop ./music-e2e --command bash -euc '
 cd /mnt/holochain/holochain-music/music-e2e
 cargo test --test s14_verified_seek_repair_sweettest -- --nocapture
'
```

**Pass is not assumed:** the Rust integration was not compiled or executed in
the authoring environment. Expected after successful Ubuntu testing:

```
test bob_repairs_missing_ciphertext_and_replays_verified_wav_range ... ok
test result: ok. 1 passed; 0 failed
```

Test asserts authenticated streaming overlap, one genuinely missing CAS object,
S4 signed receipt and full ciphertext recovery, two identical nonzero WAV
seek ranges, verified full PCM samples/hash, correct 4,000 seek frames and the
64 KiB bound. It uses the `null` audio backend in CI, or `alsa` only when
explicitly requested by the user as a hardware test:

```bash
export HOLOCHAIN_S14_AUDIO_BACKEND=alsa
nix develop ./music-e2e --command bash -euc '
 cd /mnt/holochain/holochain-music/music-e2e
 cargo test --test s14_verified_seek_repair_sweettest -- --nocapture
'
unset HOLOCHAIN_S14_AUDIO_BACKEND
```

Do not run the ALSA test unattended or at a high audio volume. It will produce
the generated test sine-wave tone, not a commercially licensed song.
