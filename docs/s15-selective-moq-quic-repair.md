# S15 draft — Selective single-chunk ciphertext repair using pinned MoQ/QUIC

## What is implemented

S15 adds an **explicit opt-in second QUIC/MoQ session** to fetch **one**
signed S1 ciphertext object, after the original S13 stream finishes. This is
not the S14 HTTP/S4 repair fallback, nor lower-layer QUIC packet retransmission.
The original first QUIC stream and S9–S14 defaults are unchanged.

- Carol's `holochain-music-moq publish --repair-index 3` validates the S1
  signed package, sends the original track, then accepts **one more MoQ
  connection at the exact same loopback endpoint and TLS certificate**. On
  that connection it publishes the domain-separated track
  `ciphertext-repair-v1-3` with **only index 3** from the signed S1 manifest.
- Bob's new `holochain-music-moq repair-receive --index 3` opens a fresh
  cert-pinned QUIC connection to that same endpoint, subscribes to the
  matching repair track, validates object SHA-256/length against the pinned
  signed artist manifest, ignores all unrequested objects, and writes only ciphertext.
- `music_catalogue.moq_repair.repair_missing_ciphertext_over_moq` checks
  artist signature and **Holochain-verified manifest digest**, expected
  one-object-missing local CAS layout, local symlink/corruption refusal,
  existing absolute MoQ executable, exact loopback endpoint and TLS fingerprint.
  It independently verifies stored ciphertext and the full package after the
  Rust receiver returns, then returns a bounded result. Invalid reports and
  timeouts fail closed.
- `include_trust_context=True` in the S9 conductor/MoQ bridge now exposes
  `verified_moq_url` and `verified_moq_cert_fingerprint_hex`, **from Carol's
  host-authored Holochain DHT endpoint** and validated against pinned DNA,
  agent author and signed S4 receipt before the first MoQ download.
  The receiver never trusts a host's local ready JSON for its endpoint or pin.
- S15 Rust Sweettest starts Alice, Bob and Carol as three actual Holochain
  conductors, verifies a complete S13 granted stream and adaptive PCM, deletes
  Bob's single local ciphertext object, then repairs it **exclusively over
  pinned MoQ/QUIC**, without requesting an S4 HTTP chunk. Frame-exact seek
  and replay both match independently generated PCM hashes.

## Honest scope boundary

**The repair index is preselected by Carol's test-process arguments.** This
first S15 slice proves *selective one-object MoQ transfer on a second pinned
QUIC session*, but does **not** yet implement a generic network protocol by
which Bob can request *arbitrary* missing indices from a long-lived publisher,
multiple simultaneous recovery requests, a transport-loss reconnect strategy,
or automatic retransmission during initial streaming. It also does not repair
corrupt local objects or guarantee host availability. The next S15 extension
needs listener-to-publisher control messages, bounded request rate/selection,
replay-resistant authorization where required, and explicit multi-index cases.

No private keys, content keys or plaintext ever go through S4, Holochain or
MoQ. A valid artist-signed grant is still required for any decrypted playback;
repairing public ciphertext alone grants no playback right. No new DNA schemas.

## Ubuntu verification (on top of draft S14 PR #18)

Do not reset Cargo caches, remove the saved S9 DNA or discard local changes.

```bash
cd /mnt/holochain/holochain-music
git status
git fetch origin
git switch --track origin/feat/s15-selective-moq-quic-repair
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_s15_selective_moq_repair.py -v
# Rebuild required: S15 changes the MoQ executable.
cargo test --manifest-path crates/moq-music/Cargo.toml
cargo build --manifest-path crates/moq-music/Cargo.toml

mkdir -p /mnt/holochain/tmp
export TMPDIR=/mnt/holochain/tmp CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
export MUSIC_STORAGE_DNA=/mnt/holochain/tmp/music_storage_s9_1793906946.dna
export HOLOCHAIN_MUSIC_PYTHON="$PWD/.venv/bin/python"
export HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node"
export HOLOCHAIN_MOQ_BIN="$PWD/crates/moq-music/target/debug/holochain-music-moq"

nix develop ./music-e2e --command bash -euc '
  cd /mnt/holochain/holochain-music/music-e2e
  cargo test --test s15_selective_moq_repair_sweettest -- --nocapture
'
```

The Ubuntu integration is a **verification requirement**, not a passing result
until executed. The expected Rust test name is
`bob_repairs_one_missing_chunk_over_pinned_moq_and_replays_wav`.

Optional local ALSA after silent test succeeds:

```bash
export HOLOCHAIN_S15_AUDIO_BACKEND=alsa
nix develop ./music-e2e --command bash -euc '
  cd /mnt/holochain/holochain-music/music-e2e
  cargo test --test s15_selective_moq_repair_sweettest -- --nocapture
'
unset HOLOCHAIN_S15_AUDIO_BACKEND
```

CI also runs all earlier S9–S14 conductor tests plus S15. The authoring
environment lacks native Holochain/MoQ tools; Python fake-subprocess tests
cannot prove the second QUIC handshake, so **do not mark S15 complete** until
Ubuntu and/or the CI integration passes.
