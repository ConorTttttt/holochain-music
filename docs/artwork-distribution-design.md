# Album artwork: local groundwork and peer-delivery design

## Implemented in phase 1 (this branch)

- Artists can create an album and optionally select an **absolute PNG file path**
  in Artist Studio. The app reads the file on the same computer, not through a
  browser upload endpoint.
- Only non-interlaced **8-bit RGB/RGBA PNG** up to 1200 × 1200 and 768 KiB
  is accepted. The importer validates CRCs and compressed pixel stream, strips
  ancillary PNG chunks (including EXIF, GPS text and metadata), and stores a
  canonical file mode 0600 under the per-user host directory.
- A separate **session-token-authenticated** GET endpoint on the loopback
  server returns these local cover bytes as `image/png`. The API never accepts
  arbitrary user-supplied filesystem paths or sends tokens in image URLs.
- The browser fetches the image with an Authorization header and displays it
  via a temporary `blob:` URL. Player and library thumbnails fall back to the
  local Phosphor vinyl icon when no cover is available.
- Artist-owned tracks persist their `album_id` in the local self-licence
  metadata, so their images appear in the player even while offline.
- The static player preview can load a user's own local PNG into a visual-only
  player sample without making any requests to the backend.
- Existing audio encryption, playback/grant logic, colour themes and fonts
  are unchanged.

## Not yet implemented

**This feature does not distribute cover images over Holochain/MoQ.** Remote
listeners therefore see vinyl placeholders, not the artist's cover. Album
records still have `artwork_manifest_sha256: null` because a raw PNG hash
would **not** satisfy the intended signed manifest commitment; publishing such
a value would imply a false security guarantee.

Additionally, this first importer intentionally excludes JPEG, animated PNG,
SVG, GIF, huge/metadata-rich images and editing/replacing a published cover.
Converting other artwork formats to a standards-compliant PNG is a separate
step, ideally with pixel re-encoding in a sandboxed image decoder.

## Phase 2: authenticated cross-peer artwork (design, not shipping)

1. Define a **public-artwork package manifest** with image media type, length,
   pixel dimensions and a SHA-256 digest for each bounded chunk. Use a
   cryptographic signature from the artist's trusted S2 owner signing key.
   Artwork is public and has **no audio decryption key**; music grants must not
   be exposed or reused for it.
2. Bind the signed artwork manifest digest to the authenticated album record
   using the existing `artwork_manifest_sha256` field **only after the manifest
   scheme is specified and verifiable**. Ensure same-artist ownership and
   prevent file substitution.
3. The current Holochain album v1 records are append-only and `list_albums`
   uses the first record seen per album ID. **Updating an existing album's
   artwork reference requires an explicitly versioned album metadata model**
   and coordinated DNA migration; simply republishing the v1 ID is unsafe.
4. Retrieve public artwork over authenticated/pinned MoQ/QUIC endpoints or a
   similarly verified content-addressed transport. Do not trust arbitrary
   artist-provided HTTP URLs; always verify the manifest signature and content
   hashes and enforce transfer/decoding size limits.
5. Cache verified cover bytes for offline display in the listener's library.
   Handle missing/offline artist hosts, changes to cover versions and local
   cache eviction without blocking audio playback.
6. Test with two separate Holochain agents/computers, including mismatched
   hashes, forged authors, malformed images, offline restarts and Windows
   packaging, before claiming listener-side artwork availability.

## Review / local testing

```bash
python3 -m unittest discover -s tests -p 'test_album_artwork.py' -v
python3 -m unittest discover -s tests -p 'test_ui_player_polish.py' -v
```

For a browser-only preview (works without Holochain):

```bash
python3 -m http.server 8766 --bind 127.0.0.1 --directory holochain_music/ui
```

Open `http://127.0.0.1:8766/player-preview.html`, select a PNG from your
computer and inspect the new artwork slot in Ocean Signal and Amethyst themes.
