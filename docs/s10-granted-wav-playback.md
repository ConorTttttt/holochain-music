# S10 (draft) — owner-granted content keys and bounded PCM playout

**Status:** First owner-signed X25519 content-key grant, AES-GCM decryption and
real-WAV PCM sink implemented; local Python security tests and offline WAV
fixture verified. **Three-conductor + S4 + S9 MoQ + grant + PCM Sweettest needs
Ubuntu/CI confirmation. No physical sound device was used.**

## End-to-end goal

```
Alice (artist)                         Holochain S5/S2 + real S4/MoQ
  Ed25519 S1 manifest ----------------> Alice's signed track and commitment
  AES-256-GCM content key ------------> stored ONLY by the artist/issuer
  S1 ciphertext chunks --------------> Carol's S4 replica + MoQ/QUIC publisher
                                           |
Bob (separate Holochain listener)      Carol host-authored Holochain MoQ URL/pin
  verifies S9 track, host receipt, cert ----> receives signed ciphertext chunks
  creates X25519 listener keypair
  requests grant out of band          <-- Alice signs and encrypts S1 key to
                                          Bob's X25519 public key, for Bob's
                                          Holochain agent + exact file/digest
  independently verifies artist/expiry/listener/file, decrypts AES key locally
  verifies every S1 ciphertext chunk and AES-GCM tag
  reads actual RIFF/WAVE PCM16 header, pushes bounded 16KiB blocks to PCM sink
```

## What S10 DOES authenticate

- **Grant issuer:** Ed25519 signature must match the same S2 `owner-manifest`
  public key already validated in Bob's authenticated, two-DNA conductor.
  `include_trust_context=True` in `receive_moq_from_live_conductor` exposes
  only that verified **public** key and verified Bob/Alice agent IDs.
- **Grant listener:** signed `listener_agent` must equal the agent from Bob's
  trusted local conductor. Decryption requires the matching X25519 private
  key (never carried on Holochain, S4 or QUIC). Alice's test issuer creates
  an ephemeral X25519 key and wraps the 32-byte AES key with X25519 ECDH,
  HKDF-SHA256 and AES-256-GCM with file/agent/date domain separation.
- **File and expiry:** `file_id`, full signed S1 `manifest_sha256`, owner agent,
  recipient public key, issue time and expiration are all signed. Grants
  expire within 24 hours of issuance (test uses one hour). No grant = no
  authorised local decryptor output. Wrong key/file/artist/reader/expiry,
  invalid WAV or corrupted chunk is rejected.
- **Audio integrity:** full S1 CAS hash verification occurs before PCM output;
  each AES-GCM chunk is authenticated before its plaintext is sent to the
  PCM sink. Supported format is canonical uncompressed RIFF/WAVE PCM16 mono
  or stereo at specified common sample rates. The sink is fed at most 16 KiB
  per call; plaintext is not written to a separate reconstructed WAV file.

## Trust boundaries still NOT implemented

1. **Buyer identity and payment entitlement:** the grant **issuer** must
   authenticate that Bob controls the supplied X25519 public key and decide
   whether he should receive it (e.g. via payment/licence). The current test
   orchestrator intentionally makes that decision as a trusted local fixture.
   An X25519 public key and a string naming Bob are not a cryptographic proof
   of that binding by themselves. This prototype is an *owner-issued grant*,
   not a commercial rights/payment engine.
2. **Revocation and rotation:** signed offline grants can be used until expiry;
   revoking one requires an online enforcement/key-rotation design. A copy of
   an already-decrypted track cannot be cryptographically clawed back.
3. **Physical playback:** the Sweettest feeds a PCM hash sink to prove actual
   decoded sample bytes/frame count, **not ALSA/PulseAudio speakers**. No
   buffering clock, pause, seek, continuous MoQ stream or adaptive QoS yet.
4. **Local-only network:** S9's QUIC/S4 local bind rules remain, not a public
   relay/NAT deployment. The S10 test runs **Alice, Bob and Carol as three
   independent Sweettest Holochain conductors**, not three machines.
5. **Memory:** one decrypted S1 chunk (up to 4 MiB) plus a 16KiB PCM block is
   buffered, not the whole WAV. An AES key necessarily exists in the
   authorised reader's process memory while decrypting. Python is not a
   hardened key-erasure environment.

## Ubuntu verification

S10 uses **the existing working S9 storage DNA**. It introduces no DNA/zome
schema changes and requires no re-pack. Retain your saved S9 bundle path:

```bash
cd /mnt/holochain/holochain-music
git status
git fetch origin
git switch --track origin/feat/s10-owner-granted-wav

source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_s10_granted_audio.py -v

mkdir -p /mnt/holochain/tmp
export TMPDIR=/mnt/holochain/tmp CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
export MUSIC_STORAGE_DNA=/mnt/holochain/tmp/music_storage_s9_1793906946.dna
# If that filename no longer exists, find your latest *S9* bundle with:
ls -lh "$MUSIC_STORAGE_DNA" music-dna/workdir/music_catalogue.dna
export HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node"
export HOLOCHAIN_MOQ_BIN="$PWD/crates/moq-music/target/debug/holochain-music-moq"
export HOLOCHAIN_MUSIC_PYTHON="$PWD/.venv/bin/python"

nix develop ./music-e2e --command bash -euc '
  cd music-e2e
  cargo test --test s10_granted_moq_playback_sweettest -- --nocapture
'
```

On some shells, `nix develop ./music-e2e --command` may have different inherited
environment handling. The test needs the absolute `MUSIC_STORAGE_DNA`, S4 and
MoQ executable paths from above. If an executable or DNA path is missing,
resolve that before starting the expensive real-conductor test.

**Expected only after Ubuntu/CI verification:**

```
running 1 test
test bob_discovers_moq_and_plays_owner_granted_wav_pcm ... ok
test result: ok. 1 passed; 0 failed
```

The Python tests require no Holochain/Nix or physical audio device. The new
Rust Sweettest retains S9's real signed S4 receipt and verified QUIC host
endpoint checks, verifies cross-agent endpoint forgery is refused, and adds
explicit grant issuance, secret removal and exact authenticated PCM sample
recovery. The original S7/S8/S9 tests remain available and unchanged.
