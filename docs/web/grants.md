# Grants, licences and private delivery

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
which also records Python's own verdict. Node (OpenSSL) and Chromium
(BoringSSL; 157 locally, 143 in CI) agree with Python on all 23 cases: valid grant, valid licence,
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

## Private delivery over Holochain (this round)

The native workflow is used unchanged (`dna/coordinator/src/lib.rs`):

```
listener  send_access_request ──call_remote──► artist  receive_access_request
          (provenance = listener agent; carries x25519_public_hex)       → private InboxAccessRequest
artist    send_grant          ──call_remote──► listener receive_grant
          (provenance = artist agent)                                   → private InboxGrant
```

The remote call's **provenance** binds the listener's X25519 key to their
Holochain agent; the artist approves in the native app
(`MusicApp.artist.grant()`); the grant lands as a private entry on the
listener's own chain. HWC and the candidate gateway now carry standard
`call_remote` in both directions — see [call-remote.md](call-remote.md).

### Browser states (`web/src/app/main.js`, `data-access-state`)

| State | Shown when | Established by |
| --- | --- | --- |
| `none` | no request, no grant | local |
| `sending` | request in flight | — |
| `awaiting` | `send_access_request` returned Ok: the artist's conductor stored the private request | the artist's own `ZomeCallResponse::Ok` |
| `unavailable` | artist node unreachable, or it refused the delivery (rate limit, invalid) | the error; explicitly "nothing approved or declined" |
| `checking` | reading the private inbox | — |
| `granted` | a grant from `get_inbox_grants` (or the recovery import) verified for this agent, key and exact manifest; "Playback authorised" | local verification |
| `expired` | stored streaming grant past `expires_at` (stays expired after restart: every playback re-verifies) | local verification |
| `rejected` | a delivered/imported grant failed verification | local verification |
| `unsupported` | the browser conductor cannot make remote calls | HWC error |

Music has no "declined" message, so the browser never claims a decision it
has not received. The request log (`RequestLog`, per agent, public facts only)
only drives the "awaiting" text.

### Recovery import

The "Recovery: import a grant file received outside Holochain" control is a
collapsed diagnostic. It applies exactly the same verification, does not
authenticate the X25519 key to the artist, and is not used by the acceptance
checks (it is used only to feed grants that must be **rejected**: tampered,
other track, other listener).
