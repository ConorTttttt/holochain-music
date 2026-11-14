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
    unrestricted capability grant). Inboxes are rate-limited: 20 per sender per
    24 h and 500 from all senders per hour. Refusals are explicit and are never
    retried as if the recipient were offline.
  - Undeliverable messages (recipient offline or busy) wait in a local outbox
    and are retried every 30 s for up to 7 days while the app runs.
  - Full review for approval: [private-grant-security-review.md](private-grant-security-review.md).

### Metadata that remains visible (unavoidable with this design)

- The *action* of a private entry (entry type, entry hash, timestamp, sequence)
  is published in the author's agent activity. Observers learn "artist X
  received N access requests at these times" and "listener Y received N grants".
  They do not learn which track or which counterparty. Entry hashes are not
  feasibly linkable: the recipient adds a random 16-byte nonce to every request
  entry, and grants contain random salts and nonces.
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

### 5a. Windows port (same model, different OS mechanisms)

| Linux | Windows | Notes |
|---|---|---|
| Data dirs 0700, key files 0600 (`O_EXCL`, `O_NOFOLLOW`) | `%LOCALAPPDATA%\HolochainMusic\{data,config}` with a **protected DACL**: full control for the current user and SYSTEM only, inherited by every file created inside (`holochain_storage/portable.py`) | Key reads refuse any file whose DACL grants another account (allowed: user, SYSTEM, Administrators, mirroring root on Linux), and refuse symlinks/reparse points. NULL DACLs and object ACEs fail closed. |
| Lair keystore on a Unix socket in the conductor dir | Lair's named pipe (lair 0.7.1 default on Windows) | Passphrase: the same random key file, piped on stdin. |
| `fcntl.flock` single instance | `msvcrt.locking` on `app.lock` | |
| Children stopped with SIGTERM/SIGKILL | Children have **no console** (`CREATE_NO_WINDOW`) and live in a **kill-on-close Job Object**, so a crashed or killed app never leaves an orphan conductor or MoQ host. Stop is `TerminateProcess`. | Equivalent for the conductor: it has no SIGTERM handler on Linux either. |
| `select()` on child pipes | One bounded reader thread per pipe (32 × 64 KiB queue) | Same size limits as before; output is still JSON-lines validated. |
| ALSA `aplay` | WASAPI shared mode via PortAudio (`music_catalogue/audio_output.py`) | Receives only PCM that already passed the grant gate, SHA-256 and AES-GCM; ≤ 200 ms queued; abort discards at once. ASIO is not shipped. |
| Firewall: user-managed `ufw` | Installer adds **program-scoped inbound rules on the Private profile only** (`holochain.exe`, `holochain-music-moq.exe`, `kitsune2-bootstrap-srv.exe`) | Nothing is opened on Public/Domain networks. No other Windows protection is changed. The uninstaller removes the rules. |
| `.deb` from a trusted builder | **Unsigned** NSIS installer | SmartScreen warns. Users verify the SHA-256 out of band. Code signing is required before any public release. |

A new local-API route, `POST /api/shutdown`, lets the Start-menu "Quit"
entry stop a console-less app. It has the same token, Host and Origin
requirements as every other route. `holochain-music quit` reads the token from
`data/session.json`, which has the same protection as the key files. Any
process that can read that file could already read the keys.

Windows-specific residual risks: (1) other processes running as the same user
can read the data, as on Linux; there is no DPAPI/Credential Manager
integration. (2) Administrators can read everything. (3) The bundled Python
runtime and DLLs are protected only by the Program Files ACL. (4) The upstream
Holochain binaries are verified by pinned SHA-256 that matches GitHub's
recorded digests, not by a publisher signature.

## 6. Resource bounds

Per-session (512) and per-host (64) MoQ request limits; host send rate cap;
≤ 64 objects per request; ≤ 256 objects per fetch; manifest ≤ 8 MiB, receipt
≤ 16 KiB, grant ≤ 8 KiB; bridge replies ≤ 4 MiB; progress output bounded;
download retries exponential up to 16 s and ≤ 6 consecutive failures, then the
explicit `unavailable` state.

## 6a. Signing-key binding assurance (S2 key-binding v2)

The deployed storage DNA (`dna/`, `holochain-storage/key-binding/v1`) checks
only that a key binding is *authored* by the agent it names; any agent can bind
another agent's *public* key. Ciphertext integrity and grants are unaffected,
but attribution of content and hosts is weaker than signature-level identity.

`dna-v2/` is a separate, opt-in storage DNA (`music_storage_v2`) whose
integrity zome accepts only `holochain-storage/key-binding/v2` bindings
carrying an Ed25519 proof of possession by the bound key, over a
domain-separated statement of DNA hash, agent, purpose, key and generation.
It refuses v1 bindings. The v1 DNA and its hash are unchanged; the app still
uses v1 by default (`ArtistService(key_binding="v2")` is an explicit opt-in).
See `docs/s2-key-binding-v2.md`.

## 6b. Signing-key lifecycle (S2 key lifecycle v2.1)

`dna-v21/` is a third, opt-in storage DNA (`music_storage_v21`). Each agent
has one validated key lineage per purpose:

* **Inception.** The first generation proves possession of its key.
* **Rotation.** The new key proves possession and the old key signs
  continuity.
* **Recovery.** Used for a lost key: agent-authorised, no continuity, and
  labelled as such.
* **Revocation.** Agent-authorised, with scope `new-operations` or
  `compromised`.

Integrity validation reads the author's own chain, so skipped generations,
forks, replays, key reuse, and cross-purpose or cross-DNA transitions are
refused. The Holochain agent is the only lifecycle authority. A stolen
*media* key cannot rotate or revoke for its owner, but a stolen *agent* key
can; agent-key rotation is outside v2.1.

Readers resolve the lineage by predecessor references, never timestamps.
Content anchored on the owner's chain while its key was valid stays
verifiable after rotation or revocation. Revocation cannot recall exported
plaintext.

`replica-receipt/v2` names the host agent and its exact key generation; S1
receipts are unchanged. The app default is still v1:
`ArtistService(key_binding="v2.1")` is an explicit opt-in. See
`docs/s2-key-lifecycle-v21.md`.

## 7. Needs independent review before production

The private-inbox design (§3), the unrestricted remote-call capability, key
storage without an OS keyring, the self-signed pinned TLS for LAN hosts, the
kitsune2 relay exposure, and the bundled Holochain binaries' supply chain.
