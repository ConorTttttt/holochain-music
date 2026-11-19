# Grants, licences and the private-delivery blocker

## What is compatible today

The browser implements the **unchanged v1 formats** of
`music_catalogue/content_grants.py` in `web/src/security/v1.js`:

* `holochain-music/content-grant/v1` (streaming, ≤ 24 h, 120 s clock skew) and
  `holochain-music/personal-licence/v1` (perpetual personal use);
* artist Ed25519 signature over canonical JSON (byte-exact port of
  `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`);
* listener-specific X25519 → HKDF-SHA-256 (exact transcript/context strings,
  separate domains for grant and licence) → AES-256-GCM key wrap;
* binding to the exact signed manifest digest, file ID, owner agent and
  listener agent; trusted artist key from the S2 `owner-manifest` binding
  read through the listener's own cell — never from `grant.signer`.

Vectors come from the native code (`web/tests/vectors/generate_vectors.py`),
which also records Python's own verdict. Node (OpenSSL) and Chromium 157
(BoringSSL) agree with Python on all 23 cases: valid grant, valid licence,
duplicate delivery, wrong recipient key, wrong listener, cross-listener reuse
(with and without the other listener's identity), wrong owner, forged by another
artist, wrong trusted key, grant for another file, wrong manifest, tampered
wrapped key (unsigned and re-signed), tampered field, swapped signature,
expired, issued in the future, lifetime > 24 h, unsupported version, bad licence
terms, extra envelope field, missing body field.

Grants are stored in the browser as the signed, still-wrapped JSON. They are
re-verified before every playback; unwrapped content keys exist only as
non-extractable AES-GCM `CryptoKey`s in memory. A licence is never replaced by
a time-limited grant; re-delivery of an identical grant is idempotent.

## The blocker: Music's private request/grant transport

The native workflow (`dna/coordinator/src/lib.rs`):

```
listener  send_access_request ──call_remote──► artist  receive_access_request
          (provenance = listener agent; carries x25519_public_hex)       → private InboxAccessRequest
artist    send_grant          ──call_remote──► listener receive_grant
          (provenance = artist agent)                                   → private InboxGrant
```

The remote call's **provenance** is what binds the listener's X25519 key to
their Holochain agent; the artist approves in the native app; the grant lands
as a private entry on the listener's own chain.

Exact gaps at the pinned baseline (all reproduced in the interop test):

1. **HWC cannot make remote calls.** `packages/core/src/ribosome/host-fn/call.ts`
   supports only `CallTarget::ConductorCell(Local)`. `send_access_request`
   fails inside the browser with `[HostFn:call] No ConductorCell in target`
   (check E1). Nothing is sent; the UI says so.
2. **The gateway drops incoming remote calls for browser agents.**
   `h2hc-linker` `src/gateway_kitsune.rs` forwards only `RemoteSignalEvt` to
   the browser; `CallRemoteReq` for a proxied browser agent is ignored. A
   native artist's `send_grant` to a browser listener therefore times out
   ("recipient unreachable") and stays in the native outbox. It does not
   falsely report delivery.
3. **HWC refuses non-author provenance.** Imposter's patch made the ribosome
   reject zome calls whose provenance is not the local agent because remote
   capability checks are not implemented. Even if (2) forwarded the call,
   `receive_grant` (provenance = artist, authorised by the `inbox` unrestricted
   cap grant) would be refused.
4. **Imposter's encrypted delivery cannot carry Music messages.** Its gateway
   frames are domain-separated (`imposter.h2hc.private-role.v1`), use
   `game_role_request` / `game_role_deliver` capabilities and a game-specific
   envelope. Reusing them would mean a second, unreviewed grant protocol.

What was implemented safely instead: everything the browser can verify
locally (recipient key, request payload in the native format, inbox sync from
`get_inbox_grants`, full grant verification and storage, playback) is in
place and ready for when a transport exists. An **"Import an artist-issued
grant"** control accepts a signed grant file and applies exactly the same
checks; the interop test uses it as an operator-assisted, out-of-band path to
exercise playback (check D1). It does not authenticate the X25519 key to the
artist — the operator must convey the browser's public recipient key and agent
key to the artist authentically — and it is not presented as Holochain
private delivery.

## Interoperability proposal

Superseded by the source-verified design in [call-remote.md](call-remote.md):
standard Holochain `call_remote` for browser agents (signed `ZomeCallParams`
over SHA-512, `CallRemoteReq`/`CallRemoteRes` through the gateway, native
nonce/expiry and capability-grant checks in HWC), no new grant format, no
Music DNA change. Its HWC-side authoriser is implemented and tested against
canonical Holochain 0.7 vectors (`web/hwc/remote-call/`); the gateway work and
HWC runtime wiring remain. Private grant delivery stays **BLOCKED** until a
native artist's approval reaches a browser listener over Holochain in the
interop test; the out-of-band import is not counted as that.
