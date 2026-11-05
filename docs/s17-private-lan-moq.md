# S17 — Explicit private-LAN MoQ endpoint + pinned TLS (draft)

**Stack:** [S16 draft PR #20](https://github.com/ConorTttttt/holochain-music/pull/20). No Holochain DNA, S1 encrypted package, S10 signed owner grant, S4 node format or public HTTPS endpoint is changed. S9–S16 defaults remain loopback-only.

## What this slice enables

Before S17, the S8/S9 publisher binds only loopback and the receiver refuses a non-loopback URL. S17 adds a tightly opt-in **RFC1918 private IPv4** mode for the genuine Rust MoQ/QUIC publisher, receiver and S15 one-object repair receiver. It is a transport and trust-boundary preparation step for two real machines; **it is not a claim that separate-machine Holochain discovery or audio playback has been tested.**

- Publisher `--allow-lan --advertise-ip <private IPv4> --bind <same IP:port or 0.0.0.0:port>` is mandatory for LAN exposure. The advertised endpoint uses the explicit LAN address and *actual bound UDP port*, never an unspecified/loopback address. The default still requires a loopback binding.
- Receiver `receive` and `repair-receive` accept `--allow-lan` only for canonical `https://<RFC1918 IPv4>:<port>` URLs; reject public IPs, DNS, userinfo, path/query/fragment, link-local, multicast, IPv6, missing/zero ports. An HTTPS-looking URL is **not** an HTTPS TCP server: MoQ uses QUIC **UDP**.
- Python trusted Holochain conductor bridge uses `allow_lan_moq=True` only when explicitly requested. It still validates authenticated Bob app and both DNA pins, Carol-authored endpoint, S1 artist signature, signed S4 receipt, signer↔agent bindings, signed-manifest digest and the *Holochain-authored TLS SHA-256 certificate fingerprint* before invoking Rust.
- S12/S13 authorised adaptive PCM, S16 in-flight seeking and S15 one-object MoQ repair expose the same optional flag, preserving the default locked-down API. Plaintext/AES keys and X25519 private keys never enter MoQ or S4.

## Native test on Ubuntu (the current computer)

```bash
cd /mnt/holochain/holochain-music
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -p test_s17_lan_moq.py -v

export TMPDIR=/mnt/holochain/tmp CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0
cargo test --manifest-path crates/moq-music/Cargo.toml
cargo build --manifest-path crates/moq-music/Cargo.toml
```

These tests enforce the URL, authentication and opt-in contracts. They do **not** prove connectivity to a different computer. The S16 genuine localhost Sweettest remains the compatibility integration gate:

```bash
export MUSIC_STORAGE_DNA=/mnt/holochain/tmp/music_storage_s9_1793906946.dna
export HOLOCHAIN_MUSIC_PYTHON="$PWD/.venv/bin/python"
export HOLOCHAIN_STORAGE_NODE_BIN="$PWD/crates/storage-node/target/debug/holochain-storage-node"
export HOLOCHAIN_MOQ_BIN="$PWD/crates/moq-music/target/debug/holochain-music-moq"
nix develop ./music-e2e --command bash -euc '
  cd /mnt/holochain/holochain-music/music-e2e
  cargo test --test s16_inflight_moq_seek_sweettest -- --nocapture
'
```

## Separate-machine MoQ transport smoke test: procedure, not yet executed

This *requires two machines on the same trusted private LAN*. Keep the **Holochain admin WebSocket**, AES keys, X25519 private key and S4 HTTP node bound to localhost. Use an SSH tunnel or properly authenticated HTTPS if Bob needs access to S4 manifest/receipt; do not expose the S4 HTTP node in cleartext over the LAN. Arrange Holochain cross-machine bootstrap/discovery separately; the existing Sweettests create 3 conductors on one host, not 3 hosts.

1. On **Carol's host**, select its actual private IPv4 (for example `192.168.1.50`) and a UDP port (for example `4443`). Ensure only Bob's private address can reach Carol's UDP/4443 through the host firewall. Copy the **signed S1 encrypted manifest + ciphertext CAS** to Carol's host; no artist/reader private key is needed. The old publisher's artist key and signed-manifest digest inputs are public pins.
2. On Carol's host run the normal publisher with the new explicitly selected private-LAN interface:

   ```bash
   holochain-music-moq publish \
     --manifest /path/to/signed-manifest.json \
     --store /path/to/encrypted-cas \
     --trusted-artist-hex "$ARTIST_PUBLIC_KEY_HEX" \
     --expected-manifest-sha256 "$MANIFEST_SHA256" \
     --cert-dir /private/cert-dir \
     --ready-file /private/unique-ready.json \
     --bind 192.168.1.50:4443 \
     --allow-lan \
     --advertise-ip 192.168.1.50
   ```

3. Publish the **exact URL and certificate fingerprint** in Carol's **correctly authenticated Holochain S2 MoQ endpoint action**. The readiness file is **not** an authenticated source for Bob and must never silently override a DHT-verified endpoint or signer. An out-of-band, independently authenticated fingerprint is acceptable for an isolated transport smoke test; it is not a substitute for the application integration.
4. On **Bob's host**, after getting the manifest, signer and endpoint fingerprint through the authenticated application path, subscribe with the new private LAN opt-in:

   ```bash
   holochain-music-moq receive \
     --manifest /path/to/signed-manifest.json \
     --store /private/bob-received-cas \
     --trusted-artist-hex "$ARTIST_PUBLIC_KEY_HEX" \
     --expected-manifest-sha256 "$MANIFEST_SHA256" \
     --url https://192.168.1.50:4443 \
     --cert-fingerprint-hex "$DHT_AUTHENTICATED_CERT_FINGERPRINT_HEX" \
     --allow-lan
   ```

5. Verify that Bob's complete ciphertext CAS hashes against Alice's artist-signed manifest. Then use the S10 owner-signed **listener-specific** content grant and local private key to decrypt/play. Test wrong TLS fingerprint, modified ciphertext, offline host and interruption: all must fail closed. Only after a real second computer completes this sequence can S17's separate-machine transport be marked verified.

**Operational limits:** RFC1918 on one private LAN only; no DNS, NAT traversal, WAN/public endpoint, automatic reconnect, MoQ general range request, multi-machine Holochain gossip/relay automation, remote S4 HTTPS deployment, or production buyer entitlement. The certificate generation still uses the development self-signed certificate with a **sha256-pinned** verifier; it is not generally trusted CA PKI. Any real deployment needs external security and network review.
