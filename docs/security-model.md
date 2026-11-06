# Security model (v1.0.0 release candidate)

Status: describes the code on branch `feat/v1-app-integration`. Not independently
reviewed. Items marked **APPROVAL** change a trust assumption and need the
project owner's sign-off before release.

## 1. Components and what each may see

| Component | Holds | Never holds |
|---|---|---|
| Holochain DNAs (public DHT) | artist profiles, albums, tracks (title, duration, file ID, signed-manifest SHA-256), artist/host Ed25519 *public* key bindings, file commitments, host replica claims, host MoQ endpoint URL + TLS SHA-256 fingerprint | audio, ciphertext, content keys, grants, listener X25519 keys, listener↔track relations |
| Private source-chain entries | artist: received access requests; listener: received grants | anything readable by other agents |
| Host (MoQ `serve`) | ciphertext CAS, signed manifest, its own signed receipt, its TLS key | content keys, plaintext, listener keys |
| Listener app process | listener X25519 private key, grants, decrypted PCM transiently (≤ one chunk + 64 KiB queue) | artist signing key |
| Browser UI | labels, state, progress | PCM, ciphertext, grants, any key, the conductor admin API |

## 2. Cryptographically enforced

- **Ciphertext integrity**: every chunk is checked against the artist-signed S1
  manifest (SHA-256 + length) before it is stored, before it is sent by a host,
  and again before decryption. AES-256-GCM authenticates every chunk with
  file-ID + index AAD. Corrupt or substituted audio cannot reach the output
  (tests: player, streaming, e2e).
- **Artist authenticity**: the manifest signer must equal the Ed25519 key that
  the artist agent bound on Holochain; ambiguous bindings are refused.
- **Host authenticity**: the receipt must verify against the host agent's bound
  key and match the host's replica claim; the MoQ connection is pinned to the
  host-published SHA-256 certificate fingerprint (hostname ignored).
- **Listener-specific authorisation**: grants wrap the content key to one
  X25519 key with HKDF-SHA-256 + AES-256-GCM, bind owner agent, listener agent,
  file ID and manifest digest, and are Ed25519-signed by the artist.
  - Streaming grant: max 24 h lifetime, checked against the local clock.
  - Personal licence (`holochain-music/personal-licence/v1`): no expiry, domain-
    separated HKDF context so it can never be confused with a streaming grant.
- **Backups**: S1 chunked AES-256-GCM; package key wrapped with AES-256-GCM
  under scrypt (N=2^17, r=8, p=1).

## 3. Enforced by Holochain (trusting the local conductor)

- Action authorship of every public record, validated by the DNA integrity zome
  (author must equal the agent named in the entry).
- **APPROVAL – private delivery of requests and grants.** Requests and grants are
  no longer public DHT entries. They travel by Holochain `call_remote` and are
  stored as *private* entries on the recipient's chain. The sender identity is
  the remote call's **provenance as verified by the recipient's conductor**.
  - The listener's X25519 key is now authenticated by that provenance (the
    listener signed the zome call), not by a public DHT key binding.
  - The grant itself is still verified with the artist's Ed25519 key, so a
    forged delivery cannot authorise playback.
  - Only `receive_access_request` and `receive_grant` are remote-callable (an
    unrestricted capability grant). Inboxes are bounded (2000 total, 50 per
    sender).

### Metadata that remains visible (unavoidable with this design)

- The *action* of a private entry (entry type, entry hash, timestamp, sequence)
  is published in the author's agent activity. Observers learn "artist X
  received N access requests at these times" and "listener Y received N grants".
  They do not learn which track or which counterparty. Entry hashes are not
  feasibly linkable: requests contain the listener's unpublished X25519 key, and
  grants contain random salts and nonces.
- `call_remote` goes over the encrypted kitsune2/iroh transport, directly or via
  the relay. The relay and network observers can see that two peers exchanged
  traffic, and when.
- Fetching ciphertext from a host reveals the listener's network address and
  which file ID it fetched **to that host**. Hosts are chosen by the artist.
- Both peers must be online at the same time to deliver a request or grant.
  Otherwise the sender gets an explicit "recipient unreachable" error and can
  retry.

## 4. Policy assumptions (not cryptographically enforced)

- The local conductor and this user account are trusted. Malware running as the
  user can read keys and decrypted audio.
- Key files are 0600 in 0700 directories (the OpenSSH/GnuPG model), and the lair
  keystore passphrase is a random file in the same directory. **No OS keyring
  or full-disk encryption is applied by the app.** Use full-disk encryption.
- `rights_basis` is the artist's declaration. **No copyright verification.**
- A perpetual licence and its exported WAV **cannot be revoked**. Streaming
  grants expire, but a listener who controls their own clock can extend local
  validity. Expiry is a courtesy, not DRM.
- Replica claims and receipts prove acceptance at one moment, not continuing
  custody or availability.
- First-install DNA pinning is trust-on-first-use of the bundled hApp.

## 5. Local attack surface

- The UI/API binds 127.0.0.1 only and needs a 256-bit per-launch bearer token,
  passed in the URL fragment and kept in tab sessionStorage. POSTs also need a
  loopback Host and Origin. Query strings are refused, bodies are ≤ 16 KiB with
  exact keys, the CSP is strict, and catalogue text is rendered with textContent
  only.
- The conductor admin WebSocket is loopback-only and limited to the bridge's
  Origin. Before this fix, any web page could connect (verified, then fixed;
  see release readiness D12).
- The MoQ host listens on loopback by default. LAN exposure needs an explicit
  bind/advertise setting, and listeners must opt in to RFC1918 endpoints.

## 6. Resource bounds

Per-session (512) and per-host (64) MoQ request limits; host send rate cap;
≤ 64 objects per request; ≤ 256 objects per fetch; manifest ≤ 8 MiB, receipt
≤ 16 KiB, grant ≤ 8 KiB; bridge replies ≤ 4 MiB; progress output bounded;
download retries exponential up to 16 s and ≤ 6 consecutive failures, then the
explicit `unavailable` state.

## 7. Needs independent review before production

The private-inbox design (§3), the unrestricted remote-call capability, key
storage without an OS keyring, the self-signed pinned TLS for LAN hosts, the
kitsune2 relay exposure, and the bundled Holochain binaries' supply chain.
