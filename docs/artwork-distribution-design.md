# Album artwork over authenticated Holochain/MoQ

## Phase 1 (merged previously)

Artists import stripped, bounded 8-bit RGB/RGBA PNGs, attach tracks to albums
and see their covers on their own machine. See `holochain_music/artwork.py`.
The original v1 album records used `artwork_manifest_sha256: null`.

## Phase 2 (this pull request; pending testing)

**New albums only:** The artist's existing Ed25519 S2 owner signing key signs an
S1-format manifest for the scrubbed PNG. The new v1 album's
`artwork_manifest_sha256` field pins SHA-256 of the **full signed manifest**,
not a naked PNG digest. This needs **no new Holochain entry type, no DNA
migration and no change to existing audio ciphertext/grants.**

The artwork file ID and its S1 AES-GCM wrapping key are **publicly derived**
from a domain-separated hash of the authenticated Holochain artist agent and
32-character album ID. This is a transport-compatibility layer and **does not
protect artwork confidentiality**. The key is intentionally unrelated to and
cannot derive any audio content key. Fresh random nonces are used per chunk;
album IDs are immutable in v1.

The resulting package is uploaded to the artist's existing S1 ciphertext CAS.
As with music, the artist authors an S2 file commitment and host replica claim;
the host serves a signed manifest and signed storage receipt and publishes its
MoQ endpoint with the existing pinned self-signed TLS certificate.

A listener resolves the album from their **local validating conductor** and
verifies the authenticated author, manifest digest, the artist's unambiguous
S2 signing-key binding and Holochain file commitment, the host binding, signed
storage receipt, replica claim, and pinned MoQ endpoint. MoQ fetch verifies
ciphertext chunk hashes; public-key-derived decryption additionally verifies
AES-GCM authentication and a bounded canonical PNG. No arbitrary artist HTTP
URLs, image proxying, browser-secret query parameters or licence material are
involved.

The UI requests the cover from the listener's own authenticated loopback app.
The app limits concurrent MoQ image fetches to two, returns HTTP 202 while
verification is in flight, and uses a fallback vinyl icon on failure. Cache
entries are separated by artist identity, persisted under the user's library,
and rechecked against signed ciphertext on subsequent offline reads.

## Compatibility and limitations

- **Existing published albums** cannot be upgraded safely by reposting album
  v1 metadata; `list_albums` currently deduplicates by first record observed.
  Such albums retain a local-only cover unless recreated as a new album.
  A separately designed/versioned album-update model and DNA migration is
  needed to edit existing album artwork without ambiguous DHT order.
- This is limited to RGB/RGBA PNG (no JPEG, SVG, GIF or APNG) at maximum
  1200 × 1200 and 768 KiB. The first-stage importer removes ancillary chunks.
- To fetch artwork from a peer, the artist's MoQ host must be reachable.
  LAN playback uses the same explicit `allow_lan` setting and IPv4
  restrictions as the current audio stack. The cover can be public even
  when the audio itself requires a grant.
- Cached public artwork is **not an audio decryption key** and does not change
  any listener licence, offline rental or music access policy.
- This implementation **has not yet been tested with two live conductors
  and MoQ hosts**. The branch must remain unmerged until local Python suites,
  security regression checks and at least one real two-device test are run.
- Per-cover cache limits exist, but no global artwork cache eviction policy,
  cover replacement UI, source-image conversion or cross-device migration
  has been implemented.

## Suggested local verification

```bash
python3 -m unittest discover -s tests -p 'test_album_artwork.py' -v
python3 -m unittest discover -s tests -p 'test_artwork_transport.py' -v
python3 -m unittest discover -s tests -p 'test_artwork_catalogue.py' -v
python3 -m unittest discover -s tests -p 'test_ui_player_polish.py' -v
python3 -m unittest discover -s tests -p 'test_ui_typography.py' -v
python3 -m unittest discover -s tests -p 'test_ui_ocean_signal.py' -v
python3 -m unittest discover -s tests -p 'test_ui_phosphor_icons.py' -v
node --check holochain_music/ui/app.js
```

### Two-device smoke test (must run before merge)

1. Use two separate Holochain agents/data directories, Alice (artist) and
   Bob (listener). Confirm both are on the same compatible DNA and can
   already see normal music catalogue and pinned MoQ endpoints.
2. Alice creates a **new** album with a stripped PNG cover and publishes an
   audio track assigned to that album. Verify Alice's host is running.
3. Bob opens **Browse** or Alice's artist page. When connectivity allows,
   the cover should replace the vinyl placeholder. Without a music grant Bob
   should still be able to see the public cover.
4. Restart Bob in `--offline` mode and open a cached library track from that
   album. Its verified artwork should still display.
5. Reject compromised/corrupted CAS chunks, forged artist signatures,
   wrong album IDs, wrong host certificate fingerprint and mismatched
   catalogue pins. Confirm none is shown and music playback continues.
