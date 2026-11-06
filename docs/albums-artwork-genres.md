# Albums, covers and genres (artist studio)

## Creating an album from songs you already published

1. Open **Artist studio → Albums & artwork**, then choose **Create album**.
2. Enter the album title, optional release date and up to six comma-separated genres.
3. Optionally choose JPEG, PNG or WebP cover artwork. The browser crops/resizes
   it to a square and compresses to public WebP before uploading.
4. Tick any songs you previously published, enter an order number for each
   (low to high), and select **Create album with selected songs**.
5. Open **Edit album and songs** later to add, remove or reorder songs, replace
   the artwork, or edit the title/date/genres. A song removed from an album is
   returned to the singles list. A song moved from another album is no longer
   shown under the previous album.

**No audio is uploaded again when assigning songs to an album.** The artist
publishes new public *metadata records* under the existing track ID; the
encrypted file ID, signed manifest, track duration, format and rights claim
are held immutable across revisions. Existing listener grants and perpetual
personal-use licences remain bound to the original file.

The album and song metadata edits consist of multiple Holochain operations;
they are **not one distributed transaction**. If an operation is interrupted,
the UI shows the number of songs successfully changed. Refresh and reconcile
the album before trying again.

## Song genres and artwork

Open **Your releases → Edit song**, choose up to six distinct genres, an optional
album and track number, and optionally replace its artwork. For new music, the
**Publish a track** form also accepts genres, cover art and an existing album.

Genres are public artist-supplied text tags, 1–32 UTF-8 bytes each. The
catalogue searches both titles and genres, but the search index is still
small-scale and not a production-size global index.

## How cover artwork is handled

Cover artwork is **public**, not encrypted or license-gated. The browser strips
metadata through a canvas re-encode, generates a small square WebP and uploads
at most 32,768 bytes per image. The conductor-authored Holochain `Artwork`
entry stores its MIME type, base64 image and SHA-256 digest, linked to the
artist's agent. Songs and albums reference the digest. A listener verifies
the owning artist's authenticated record, digest, MIME and basic image
signature before the image reaches the UI. The browser uses a blob URL to
display the verified image; no JavaScript is injected into document markup.

This bound keeps the MVP simple but is not designed for full-resolution cover
distribution or high-volume artists. A later revision should use a verified
public content-addressed media host/MoQ path or a separate image CDN/cache
rather than placing large images in DHT entries.

The loopback-only artwork upload has an increased (60 KiB) POST-body cap,
compared with 16 KiB for ordinary API requests. Server/CSP checks still
require the local bearer token, origin and host. The conductor bridge retains
its 64 KiB incoming-message cap, so the cover bound fits within it.

## Compatibility and release gates

- The catalogue adds **optional, defaulted** `artwork_sha256` and `genres`
  fields to Album and Track entry types; older records are interpreted with
  no new artwork/genres. Old profile and track IDs remain stable.
- New `Artwork` entry and `AgentToArtwork` link types are appended so
  the existing entry/link enum positions are not reassigned.
- These changes create a **new DNA hash**. Existing installed hApps and
  older conductors need an explicit coordinated DNA upgrade/migration plan
  before this feature can be released. Do not install a changed DNA over an
  active database without testing the migration.
- Rebuild the Rust `music_app_bridge`, music DNA and hApp bundle, and rerun
  author/listener cross-conductor discovery tests; do not use the previous
  rc1 package as proof of these new features.
- Rights to uploaded artwork are the artist's responsibility; no automated
  copyright verification is provided.
