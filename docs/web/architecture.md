# Architecture

```
 Chromium profile                                         Operator / native side
 ┌───────────────────────────────────────────┐
 │ Music web client (web/)  — static files   │
 │  app/ UI (desktop app.css, fonts, icon)   │
 │  adapters/holochain  ── window.holochain ─┼─► HWC extension (Lair keys, source chain,
 │  adapters/catalogue                       │     Music WASM for BOTH roles, signing)
 │  adapters/grants (X25519 key, grants)     │        │ authenticated WebSocket (admission)
 │  adapters/media ─────── HTTPS GET ────────┼──┐     ▼
 │  player/ (verify → AES-GCM → AudioWorklet)│  │  H2HC gateway (accepted Imposter build)
 │  security/v1.js (WebCrypto only)          │  │     │ kitsune2 / iroh relay
 └───────────────────────────────────────────┘  │     ▼
                                                │  Holochain 0.7 network: native Music artist,
                                                │  native Music peers (DHT authorities)
                                                ▼
                                     web media adapter (ciphertext only)
                                                │ pinned MoQ/QUIC (unchanged protocol)
                                                ▼
                                     native `holochain-music-moq serve` host
```

## Responsibilities

**User interface** — `web/public/index.html` uses the desktop app's DOM
structure, and the build copies the desktop `app.css`, Inter fonts and icon
byte-for-byte. Web-only additions live in `web/public/web.css`. No framework,
no bundler: native ES modules, so what is reviewed is what runs.

**Holochain connectivity** — the HWC extension holds the listener's identity
(Lair), runs the unchanged Music coordinator/integrity WASM for both roles and
signs the listener's actions; the accepted Imposter H2HC gateway provides
authenticated, admission-controlled network access. `adapters/holochain/hwc.js`
only ever reports a state after checking it (extension present, origin
authorised, hApp SHA-256, exact DNA hash per role with this agent, gateway
session, real network round trip). States: `extension-unavailable`,
`authorisation-required`, `not-installed`/`installing`, `wrong-dna`,
`gateway-disconnected`, `admission-pending`, `synchronising`, `ready`.

**Catalogue** — `adapters/catalogue/catalogue.js` calls the listener's own
cells (`browse_tracks`, `search_tracks`, `list_artists`, `get_artist_profile`,
`list_albums`, `list_album_tracks`, `get_track`) and re-validates every record
with the native track contract. `resolve()` is a port of the desktop
`Catalogue.resolve()` trust chain (see [security.md](security.md)). There is no
central catalogue database.

**Audio** — `player/track-player.js` streams chunk by chunk: ciphertext from
the adapter → length + SHA-256 against the artist-signed manifest → AES-256-GCM
with the file/index-bound AAD → canonical WAV PCM16 → Float32 → AudioWorklet
(`player/pcm-worklet.js`). Look-ahead is bounded (6 s of audio, 2 ciphertext
chunks in flight). Seek restarts decoding at the chunk containing the target
frame; the adapter's transfer worker restarts the MoQ stream there.

## Decisions

### D1. Reuse the HWC + gateway baseline that Imposter proved, not a new conductor
Imposter's `followup/browser-alpha-final-acceptance` is the newest coherent
lineage (`release/browser-alpha-rc1 ⊂ followup/browser-alpha-operator ⊂
followup/browser-alpha-final-acceptance`); `feature/browser-compatibility-harness`
is the older game baseline it consumes. Its HWC patches are exactly what Music
needs for genesis with `init` capability grants and private entries.

### D2. Multi-cell routing patch for HWC (generic, in `web/hwc/`)
Pinned HWC builds every page zome call's cell from `context.dnas[0]`, so a
multi-role hApp can only reach its first role. Music's `music_storage` role
(S2 key bindings, file commitments, host endpoints, private inboxes) was
unreachable. `apply_multi_cell_routing.py` routes by `role_name` / `cell_id`,
restricted to the calling origin's own context and agent, failing closed for
unknown roles. No DNA, validation rule or Music source changed.

### D3. Two native authorities
kitsune2 grows a node's storage arc only by syncing with a peer that shares a
target arc. A lone native artist plus zero-arc browser gateways keeps an empty
arc and the gateway finds no authority ("responsive_count=0"). Any real
deployment needs at least two always-on native Music nodes (artist + peer or
operator authorities), as the Imposter operator runbook also requires.

### D4. Media transport: ciphertext-only HTTPS adapter (Option B)
Direct browser MoQ (Option A) does not interoperate with existing hosts:
* hosts speak raw QUIC MoQT draft-14 (moq-native-ietf), not WebTransport/HTTP3;
* their self-signed certificates are pinned by fingerprint; browsers accept
  `serverCertificateHashes` only for ECDSA certificates valid ≤ 14 days, which
  would change the host identity published on the DHT;
* `MoqEndpoint` URLs are DNA-validated literal loopback/RFC1918 IPv4 addresses,
  which an HTTPS page cannot reach directly (mixed content / private network
  access), and a JS MoQT draft-14 client would be a second protocol stack.

`web/adapter/media_adapter.py` is a separate GET-only service. It connects to
an unchanged host using the URL and TLS pin the *browser* read from the host's
Holochain record, reuses the desktop `Download` worker (seek-prioritised
restarts, bounded gap repair, host rotation, SHA-256-verified CAS) and serves
the host's signed manifest/receipt and ciphertext objects. It never sees keys,
grants or plaintext and is not trusted for integrity. It shares nothing with
the desktop loopback API (`holochain_music/server.py`), which stays loopback-only.

### D5. WebCrypto only
Ed25519, X25519, HKDF-SHA-256, AES-256-GCM and SHA-256 come from the browser
platform. Grants unwrap via `unwrapKey`, so content keys are non-extractable
`CryptoKey`s; the listener's X25519 key is generated non-extractable and kept
as a `CryptoKey` in IndexedDB. No cryptographic algorithm is implemented in JS.
Compatibility is proven against the native Python implementation (23 grant
vectors; Node and Chromium both agree with Python on every verdict).

### D6. Private grant delivery is not substituted
Music binds a listener's X25519 key to their agent through the provenance of an
authenticated Holochain `call_remote`. Neither HWC nor the gateway can carry
`call_remote` today, and Imposter's encrypted role frames are domain-separated
to the game. The client reports this gap instead of inventing another channel.
See [grants.md](grants.md).
