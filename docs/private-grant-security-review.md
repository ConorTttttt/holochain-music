# Private grant workflow — security review for approval (rc1)

Scope: storage DNA coordinator functions `send_access_request`,
`receive_access_request`, `send_grant`, `receive_grant`, the inbox queries, the
private entry types, and the app's `request_access`, `sync_grants`,
`ArtistService.grant` and `Outbox`. Reviewed against Holochain 0.7.0 source
(`conductor/cell.rs::handle_call_remote`, `ribosome/host_fn/call.rs`).
Evidence: §7.

**Decision requested:** approve this design as the v1.0.0 trust model, with the
residual risks in §8, or ask for changes.

## 1. Message authenticity

- The sending conductor signs the full serialised zome-call parameters
  (provenance, target cell, function, payload, nonce, expiry) with the sender's
  agent key. The recipient's conductor checks that signature against
  `provenance` **before** our function runs (`handle_call_remote` →
  `is_valid_signature`, otherwise `ZomeCallAuthenticationFailed`).
- Our receive functions take the sender only from `call_info().provenance`. No
  field the sender supplies can name a different listener or artist. *Tested:*
  Mallory's request claiming to be the listener is stored under Mallory's agent.
- A delivered grant is not trusted because of its provenance. The listener
  accepts it only if all of these hold:
  - provenance equals the track's artist agent;
  - the Ed25519 signature verifies against that artist's DHT key binding;
  - listener agent, X25519 key, file ID and manifest digest all match.

  *Tested:* a genuine licence forwarded by a third party, and a self-signed
  forgery, both import 0 and play nothing.
- Known gap (by design): the listener chooses which X25519 key to put in the
  request. A listener could ask for a grant wrapped to a key someone else holds.
  That person can then decrypt, but only by also presenting the listener's
  identity string to their own software. This is equivalent to the licensed
  listener sharing their key or an exported WAV, which a licence allows them to
  do physically anyway. It is not an escalation.

## 2. Replay protection

- Network replay of a captured call is refused by Holochain's zome-call nonce
  and expiry checks (part of the signed parameters).
- Deliberate re-sending by a legitimate sender is possible and harmless.
  Duplicate requests appear twice in the artist's list. An identical grant
  re-delivered changes nothing. *Tested:* re-delivery imports 0 and leaves the
  stored grant unchanged.
- An old **streaming** grant replayed after expiry is refused by the grant's own
  `expires_at` check. A perpetual licence has no expiry by design.
- The library never downgrades a licence to a streaming grant.

## 3. Source-chain metadata (what is public)

- Request and grant bodies are **private entries** and are not published to the
  DHT.
- Each one still produces a published *action*: author, sequence number,
  timestamp, entry type and entry hash. Anyone can therefore count requests
  received per artist and grants received per listener over time.
- Entry hashes are not linkable to tracks or counterparties:
  - **Fixed in this review:** request entries previously contained only
    guessable fields for anyone who knows the listener's X25519 key (e.g.
    another artist they had also asked). That artist could test whether the
    listener asked for a given public file ID. The recipient now adds a
    16-byte random nonce.
  - Grant entries contain the grant's random salt and nonce.
- The artist's own chain reveals request **volume and timing**. The listener's
  chain reveals grant **volume and timing**. Neither reveals which tracks.

## 4. Relay and transport visibility

- `call_remote` uses the kitsune2/iroh transport. Payloads are end-to-end
  encrypted between the two peers' endpoints.
- The bootstrap/relay operator (in v1, the person running `bootstrap-server`,
  or the local app) sees which peer endpoints talk, when, and how much data
  flows. It cannot read payloads.
- The app's relay URL is plain `http://` (`relayAllowPlainText: true`), so a
  passive observer on the path to the relay sees that framing metadata too.
  Payloads remain encrypted. For networks beyond a trusted LAN, run the
  bootstrap/relay with TLS (`--tls-cert/--tls-key`).
- Fetching audio reveals the listener's address and the file ID to the host the
  artist chose. Hosts never see keys.

## 5. Key rotation

- **Listener X25519:** one key per installation, kept in backups. No rotation
  command. If it is compromised, every grant wrapped to it is compromised;
  recovery is a new installation and new requests. Existing licences stay bound
  to the old key.
- **Artist Ed25519 (manifest + grant signing):** rotation is **not supported**.
  If an artist registers a second key, listeners refuse the artist as
  ambiguous, by design: it is safer to refuse than to guess. Compromise of this
  key lets an attacker issue grants and sign manifests for that artist.
  Recovery needs a key-rotation protocol, which is not in v1.
- **Host Ed25519 and TLS:** the TLS certificate is stable and pinned. Host key
  rotation is equally unsupported.

## 6. Simultaneous-online requirement and abuse limits

- Delivery needs both conductors online. **Mitigated:** the app now keeps a
  persistent outbox and retries every 30 s for up to 7 days while it is running.
  Requests need only the artist's DHT track record, not their host, so a
  listener can request while the artist is completely offline. Messages are
  delivered only when both apps are open at some common moment, and nothing is
  stored on third parties.
- Remote callers can reach exactly two functions (an unrestricted capability
  listing only `receive_access_request` and `receive_grant`).
- **Fixed in this review:** a lifetime cap of 2000 inbox entries let a few
  throwaway agents block an artist forever. It is replaced by 20 per sender per
  24 h and 500 from all senders per hour. "Busy" is retried; "rate limited" and
  "invalid" are refused and **not** retried. *Fixed:* such refusals used to
  arrive as network errors and would have been retried as "offline".
- Residual: Sybil spam can still add up to 500 private entries per hour to an
  artist's chain (growth of roughly tens of MB per day) and delay legitimate
  requests by up to an hour. Deleting old inbox entries needs a change to the
  integrity rules (deletes are currently refused).

## 7. Evidence

See `tests/test_v1_e2e_grant_security.py` (three real conductors: artist,
listener, attacker) and the results recorded in `docs/v1-release-readiness.md`.

## 8. Residual risks to accept or address before production

1. Public request/grant volume and timing per agent (§3).
2. Relay sees peer pairs and timing; plain-HTTP relay framing (§4).
3. No key rotation for artist, host or listener keys (§5).
4. Sybil inbox growth and up to one hour of delay (§6).
5. Messages need a common online moment; there is no third-party mailbox.
6. Independent review of the above has not been done.
