# Setup, development and reproduction

HWC is **required** for this release (Chromium-based browsers). There is no
extension-free mode yet.

## 1. Toolchain

Linux x86-64 with Git, Python ≥ 3.11 (`pip install -e .` in this repository),
Node 22, Rust stable with `wasm32-unknown-unknown`, jq, and the Holochain 0.7.0
release binaries `hc`, `holochain`, `lair-keystore`, `kitsune2-bootstrap-srv`
(checksums in `web/hwc/pins.json`). For tests: Playwright `1.57.0` Chromium and
Xvfb (extensions need a headed browser).

## 2. Build the native pieces (unchanged Music)

```bash
(cd music-dna && cargo build --locked --release --target wasm32-unknown-unknown && hc dna pack workdir)
```

```bash
(cd dna && cargo build --locked --release --target wasm32-unknown-unknown && hc dna pack workdir)
```

```bash
cp music-dna/workdir/music_catalogue.dna dna/workdir/music_storage.dna integration/workdir/ && hc app pack integration/workdir
```

```bash
cargo build --locked --release --manifest-path crates/moq-music/Cargo.toml
```

```bash
cargo build --locked --release --manifest-path music-e2e/Cargo.toml --bin music_app_bridge
```

## 3. Build the HWC extension

```bash
git clone https://github.com/Holo-Host/holo-web-conductor.git "$HWC" && git -C "$HWC" checkout 0c391226e78769d44ccb4661881ed8998b15f903
```

```bash
git clone https://github.com/ConorTttttt/imposter-holochain.git "$IMPOSTER" && git -C "$IMPOSTER" checkout a39aaf926ebcc2aadad71ee4bba0b7c2677de67f
```

```bash
bash web/hwc/build-extension.sh "$HWC" "$IMPOSTER"
```

Load `$HWC/packages/extension/dist-chrome` with **Load unpacked** in a
persistent Chromium profile. After rebuilding, press *Reload* on the extension.

## 4. Gateway (operator)

Private grant delivery needs the **call_remote candidate** gateway (the
accepted gateway plus `web/gateway/call-remote.patch`). Build it from source;
the script first reproduces the accepted source exactly, then applies the
patch and runs `cargo fmt --check`, `cargo test` and strict clippy:

```bash
git clone https://github.com/Holo-Host/h2hc-linker.git h2hc
git -C "$IMPOSTER" fetch origin "$(jq -r .gateway.recipe_commit web/hwc/pins.json)"
bash web/gateway/build-candidate.sh h2hc "$IMPOSTER" gateway-candidate
(cd gateway-candidate && sha256sum -c SHA256SUMS)
```

The binary is not reproducible bit-for-bit across machines (embedded cargo
paths); record the SHA-256 and `build-provenance.txt` of the build you deploy.

Without private grants (browse/verify only), the accepted gateway still works;
recover it from the Imposter archive ref and check it:

```bash
git -C "$IMPOSTER" fetch --depth=1 origin refs/heads/archive/browser-alpha-gateway-14428255589 && git -C "$IMPOSTER" show FETCH_HEAD:h2hc-linker-linux-x86_64.gz | gunzip > h2hc-linker && sha256sum h2hc-linker
```

Expected: `8f3f8e0b6a6fc02b27776182458cf0d970bc02f76db9f6f6b6842c04f138746f`.
Run it in authenticated mode (`H2HC_LINKER_ADMIN_SECRET`, SQLite
`H2HC_LINKER_SESSION_STORE`, `H2HC_LINKER_ALLOW_INSECURE_DEV=false`,
`H2HC_LINKER_LOCAL_AUTHORITY_FALLBACK=false`) on the same bootstrap/relay as
the native participants, behind TLS. Admit a listener after they share the
agent key shown in **Identity & network**:

```bash
curl -fsS -X POST "$GATEWAY/admin/agents" -H "Authorization: Bearer $(cat "$SECRET_FILE")" -H 'content-type: application/json' -d '{"agent_pubkey":"uhCAk…","capabilities":["dht_read","dht_write","k2","call_remote_send","call_remote_receive"]}'
```

`call_remote_send` lets the listener send access requests (signed by its own
agent only); `call_remote_receive` lets artists' grants reach it. Omit both to
admit a browse-only listener; the accepted gateway rejects these capability
names, so use plain `["dht_read","dht_write","k2"]` with it.

Revoke with `-X DELETE` and `{"agent_pubkey": …}`. Keep the admin route on
loopback; the Imposter operator runbook (`docs/installed-hwc-browser-alpha.md`
on its baseline branch) covers TLS proxying and persistence.

## 5. Native participants

Artists use the normal desktop app. The web network needs **at least two
always-on native Music nodes** on the same bootstrap/relay (e.g. the artist
plus one peer/authority) so storage arcs grow; see architecture D3. Music
endpoints are loopback or RFC1918 only (DNA rule), so the media adapter must
run where it can reach the hosts.

## 6. Media adapter

```bash
python3 web/adapter/media_adapter.py --port 8787 --allow-origin https://music.example --cache /var/lib/hm-adapter --moq-binary "$PWD/crates/moq-music/target/release/holochain-music-moq"
```

Add `--allow-lan` only if hosts advertise RFC1918 endpoints. Put TLS in front
before exposing it beyond loopback.

## 7. Web client

```bash
node web/scripts/build.mjs --out dist --happ integration/workdir/holochain_music.happ --catalogue-dna "$(hc dna hash integration/workdir/music_catalogue.dna)" --storage-dna "$(hc dna hash integration/workdir/music_storage.dna)" --gateway https://gateway.example --adapter https://media.example --origin https://music.example --release my-test
```

Serve `dist/` over HTTPS with the headers in `web/scripts/serve.mjs` (that
script is fine for localhost development:
`node web/scripts/serve.mjs dist --port 8080`).

Listener flow: open the site → approve it in the HWC window → the client
installs the checksum-verified hApp and checks both DNAs → share the agent key
with the operator for admission → **Reconnect** → browse/search → *Details* →
*Verify artist signature and hosts* → (grant) → *Play*.

## 8. Reproduce the tests

```bash
python3 web/tests/vectors/generate_vectors.py web/tests/vectors/.generated/v1.json && node --test web/tests/*.test.mjs
```

```bash
node web/tests/chromium-crypto.mjs web/tests/vectors/.generated/v1.json
```

```bash
python3 -m unittest discover -s web/adapter -p 'test_*.py'
```

Full interop (native artist + peer + gateway + adapter + real Chromium/HWC):

```bash
HOLOCHAIN_MOQ_BIN=… HOLOCHAIN_MUSIC_BRIDGE_BIN=… HOLOCHAIN_MUSIC_HAPP=… H2HC_GATEWAY_BIN=… HWC_EXTENSION_DIR=… python3 web/integration/run_interop.py --work /tmp/hm-interop
```

Add `--serve-only` to start the stack and drive it by hand (`stack.json` lists
the URLs). In sandboxes without an IPv6 stack, build `web/integration/env/ipv4only.c`
(`gcc -shared -fPIC -o ipv4only.so ipv4only.c -ldl`) and set
`HM_LD_PRELOAD=/path/ipv4only.so`; GitHub runners do not need it.
