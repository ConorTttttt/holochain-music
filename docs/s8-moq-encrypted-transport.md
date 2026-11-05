# S8 draft — ordered encrypted S1 chunks over genuine MoQ/QUIC

## Scope and security promises

The S8 MoQ test binary in `crates/moq-music` reuses **exactly the same
`holochain-moq-realtime` / `holochain-moq-protocol` Git revision** as our
separate working [Holochain MOQ](https://github.com/ConorTttttt/holochain-moq)
project (`ccd9a8e313bc588490a49adbd432964fdc6d0a3e`). That crate in turn
uses `moq-transport 0.16.2` and `moq-native-ietf 0.10.0` (IETF MoQT draft-14).
No bespoke UDP protocol, simulated QUIC or HTTP masquerading as MoQ.

- **Publisher**: reads only S4's ciphertext CAS, and validates its exact S1
  Ed25519-signed manifest and S5-style file digest and artist key pins.
- **Subscriber**: dials a real TLS 1.3 QUIC connection; checks an exact SHA-256
  certificate fingerprint, the same independent S1 artist signature/digest
  pins, ciphertext hashes/sizes, and full stream count. Each MoQ object is one
  AES-GCM ciphertext chunk in manifest index order. Bytes are written into a
  separate listener-side CAS. No decryption key is ever handed to MoQ.
- **Test**: launches the real Rust S4 HTTP node, signs and uploads a genuine
  S1 encrypted fixture, starts MoQ publisher and subscriber processes,
  decrypts the resulting listener-side CAS *only in the Python test process*
  using its local fixture key, checks the original byte digest. Wrong TLS pin,
  wrong signing key, wrong manifest pin and tampered CAS are negative cases.

Because S1 requires every chunk, this stage uses `MoqPublishNode`'s **one
ordered subgroup** rather than its live-video mode (`MoqLivePublication`),
which intentionally drops old objects for slow/late subscribers. This is
an **ephemeral one-shot transfer with no replay, resume, seek, adaptive buffer
or bandwidth control**. A dropped or missing object fails closed; a future
track-per-chunk/request protocol must explicitly address retries and seek.

### Trust boundaries not yet closed

1. The fixture passes the S1 digest/artist Ed25519 key to the MoQ programs as
   separately trusted CLI pins, **not yet automatically from Bob's S6 trusted
   Holochain conductor**. S7 already proved these pins via Holochain for HTTP
   retrieval. The next integration will supply them directly to the MoQ path.
2. The fixture reads the TLS certificate fingerprint from a **local publisher
   readiness file**. That is convenient for a local test but **not a trusted
   distribution channel**. Production must bind the endpoint + QUIC cert
   fingerprint to a host-authored validated Holochain record, with revocation.
3. MoQ serves ciphertext to any local subscriber knowing the endpoint; there
   are no listener admission grants, rights, payments, group repair or keys.
4. This prototype uses local UDP/loopback only. No publicly reachable
   endpoint, relay, NAT traversal or end-user player yet. A signed S4 receipt
   does not prove continuing custody.
5. Synthetic fixture bytes are not valid audio, and decrypting them in a
   fixture is **not** live audio playback or an entitlement grant.

## Ubuntu test

From the music repository's S8 branch, keep the existing `/mnt/holochain/tmp`
configuration and run the MoQ workspace separately to avoid recompiling the
large Holochain Sweettest conductor:

```bash
cd /mnt/holochain/holochain-music
export TMPDIR=/mnt/holochain/tmp
export CARGO_BUILD_JOBS=2
export CARGO_INCREMENTAL=0

df -h /mnt/holochain /
cargo test --manifest-path crates/moq-music/Cargo.toml
cargo build --manifest-path crates/moq-music/Cargo.toml
source .venv/bin/activate
python -m pip install -e .
HOLOCHAIN_MOQ_BIN="$PWD/crates/moq-music/target/debug/holochain-music-moq" \
HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node" \
python -m unittest discover -s tests -p test_s8_moq.py -v
```

The fixture-generated S4 HTTP and MoQ QUIC listeners are bound to
127.0.0.1 only. Neither binary accepts a remote publisher address.

**Warning:** The MoQ git-dependency compiles a new native dependency tree
(quinn, TLS, moq-rs); free space on `/mnt/holochain` matters. Don't delete
existing Cargo targets just to make it compile. Test only within trusted local
Ubuntu environment; do not bind admin or S4 HTTP interfaces publicly.
