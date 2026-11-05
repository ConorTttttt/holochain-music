# S5 — Holochain music catalogue (draft implementation)

**Status:** First reviewable slice. This is a separate music-specific DNA, intentionally independent of the S2 storage DNA, and is **not yet proven across real conductors**.

## What it does

- **Artist profiles**: an agent publishes a public name, biography and optional artwork package digest.
- **Albums**: the agent publishes albums with stable artist-local IDs, titles, optional calendar dates and optional artwork package digests.
- **Tracks**: the agent publishes tracks with stable artist-local IDs, optional album association, title, duration, disc/track order, MIME audio format, and *only* `file_id` plus `manifest_sha256` for the S1 signed encrypted-file package.
- **Rights basis**: `original_owner` or `licensed_by_rights_holder`. These are *self-declared*, not independently verified legal ownership. Purchase/licence offers belong in a separate protocol.
- **Discovery**: public artist directory; album and track lookups by artist; title search over the global public track index.
- **Metadata revisions**: publish new entries under the same artist-local IDs; the coordinator returns the newest author-created version and ignores superseded versions.

No audio bytes, encrypted chunks, full signed manifests, storage receipts or private keys are written to this DNA.

## Component boundary

```text
music-dna/                Holochain 0.7 music catalogue DNA
  integrity/              Author, shape, length, date, ID and link validation
  coordinator/            Publish, lookup and discovery zome calls
  workdir/                DNA and hApp manifests (WASM bundles not checked in)
music_catalogue/          Local S1 signed-manifest reference validation
holochain_storage/        Existing generic S1 package (unchanged)
dna/                      Separate S2 storage identity DNA (in draft PR #5)
```

The Holochain `AgentPubKey` is the publishing identity. A track's signed encrypted-package manifest uses a separate Ed25519 key; until S2 is integrated, clients must obtain the *authenticated* artist→signing-key binding from the trusted validating conductor and verify the S1 manifest with that key.

## Zome endpoints

| Coordinator function | Input | Output |
| --- | --- | --- |
| `publish_artist_profile` | `ArtistProfile` | `ActionHash` |
| `get_artist_profile` | `AgentPubKey` | `Option<AuthoredRecord<ArtistProfile>>` |
| `list_artists` | `()` | `Vec<AuthoredRecord<ArtistProfile>>` |
| `publish_album` | `Album` | `ActionHash` |
| `get_album` | `{artist, album_id}` | `Option<AuthoredRecord<Album>>` |
| `list_albums` | `AgentPubKey` | `Vec<AuthoredRecord<Album>>` |
| `publish_track` | `Track` | `ActionHash` |
| `get_track` | `{artist, track_id}` | `Option<AuthoredRecord<Track>>` |
| `list_tracks` | `AgentPubKey` | `Vec<AuthoredRecord<Track>>` |
| `list_album_tracks` | `{artist, album_id}` | `Vec<AuthoredRecord<Track>>` |
| `search_tracks` | `{query: String, limit: u8}` | `Vec<AuthoredRecord<Track>>` |

All `AuthoredRecord.author` fields are extracted from a record's actual Holochain action. **Never use an unverified external JSON `author` field as proof of identity.**

## Example track record

```json
{
  "schema": "holochain-music/track/v1",
  "artist_agent": "<verified Holochain AgentPubKey string>",
  "track_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "album_id": null,
  "title": "First Single",
  "duration_ms": 180000,
  "disc_number": 1,
  "track_number": 1,
  "audio_format": "audio/flac",
  "file_id": "<64 lowercase hex characters: S1 manifest body.file_id>",
  "manifest_sha256": "<64 lowercase hex characters: SHA256 of entire signed S1 manifest>",
  "rights_basis": "original_owner"
}
```

IDs are random 16-byte IDs encoded as 32 lowercase hex characters, chosen by the artist's client, and scoped to that agent; do not treat IDs alone as globally identifying a record. An optional album association is checked by the coordinator when publishing but is *not* an integrity-level cross-record proof. A malicious direct entry can still refer to an unavailable album. Clients must handle orphan links.

## Running tests

```bash
python -m pip install -e .
python -m unittest discover -s tests -p 'test_music_catalogue.py' -v
cd music-dna
cargo check --target wasm32-unknown-unknown
cargo test -p music_catalogue_integrity --lib
```

Install the Rust `wasm32-unknown-unknown` target. The GitHub workflow `Music catalogue tests` performs Rust/Wasm checking and the Python manifest-contract tests. Build bundles with a compatible Holochain 0.7 toolchain; only checked-in source/manifests are supplied here.

## Security and scalability

- **Self-published only** in v1. Artist collaborations, delegation and signed label permissions require a future capability/delegation design.
- **Rights basis is an assertion**, not proof of copyright or a grant to stream, distribute, sell or download. Payment and buyer licences remain independent.
- **All catalogue entries are public** and immutable; new versions supersede earlier ones in readers. No delete or privacy expectations.
- **Search is an MVP directory**, not a scalable search engine. Global `get_links` can become slow/large; full-text search, moderation, DHT pagination and index sharding are later work.
- **Only structure is checked by the DHT**. A client must verify the S1 signed manifest against a validated artist signing key, and must separately assess storage-node receipt/audit evidence.
- **No real-conductor validation yet**. Before merge: run two-conductor Alice/Bob creation/gossip/discovery tests, cross-author forgery rejection at the integrity zome, and confirm absence of media/keys in DHT entries.

## Related PRs

- [S1 — base encrypted-file package (merged)](https://github.com/ConorTttttt/holochain-music/pull/4)
- [S2 — Holochain storage identity binding (draft)](https://github.com/ConorTttttt/holochain-music/pull/5)
- [S3 — storage audits / repair (draft)](https://github.com/ConorTttttt/holochain-music/pull/6)
- [S4 — network storage service (draft)](https://github.com/ConorTttttt/holochain-music/pull/7)
