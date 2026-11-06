# Holochain Music

An artist-first decentralised music player. Artists publish encrypted tracks
and decide who may listen; listeners discover music on Holochain, receive
artist-signed licences privately, stream over certificate-pinned MoQ/QUIC, and
keep licensed music for offline playback. Built on
[Holochain MOQ](https://github.com/ConorTttttt/holochain-moq) and a reusable,
file-type-independent encrypted storage layer.

**Status: v1.0.0 release candidate. Not released.** See
[release readiness](docs/v1-release-readiness.md) for what has been verified
and what is still open.

## What works (verified on Ubuntu 26.04, one computer)

- Desktop launcher, a local browser UI (loopback, token-protected) and a
  reproducible `.deb`.
- Holochain identity per installation and a managed conductor; catalogue
  browse/search, artist and album pages.
- Artist studio: profile, WAV → AES-256-GCM encrypted package, catalogue and
  identity records, self-hosting over MoQ/QUIC with a stable pinned certificate.
- Private access workflow: listener request → artist approval → signed
  streaming grant (24 h) or perpetual personal-use licence, delivered peer to
  peer and stored as private source-chain entries.
- Streaming with per-chunk SHA-256 + AES-GCM verification, play/pause/stop,
  seek during download (transfer restarts at the needed chunk), missing-chunk
  recovery and host-outage resume, queue, playlists, history, volume.
- Downloads, offline playback with no network services, WAV export under a
  licence, and passphrase-encrypted backup/restore.

## Not in v1.0.0

Payments or purchases, copyright verification, public-internet hosting or NAT
traversal, guaranteed availability, revocation of exported copies, FLAC/MP3
input, remote-host upload, key rotation. Two-computer LAN operation is
**experimental** until it is tested on two physical machines.

## Documentation

- [User guide](docs/user-guide.md) · [Installation, LAN and tests](docs/installation.md)
- [Security model](docs/security-model.md) · [Release readiness](docs/v1-release-readiness.md) · [Changelog](CHANGELOG.md)
- Design background: [encrypted storage](docs/encrypted-storage-v1.md), [ownership and purchases](docs/ownership-and-purchases.md), milestone notes `docs/s*.md`

## Architecture

- **Holochain** (`music-dna/`, `dna/`): identity, catalogue metadata, key
  bindings, file commitments, host claims and endpoints, private request/grant
  inboxes. No audio, ciphertext or content keys.
- **Hosts** (`crates/moq-music` `serve`): ciphertext, signed manifest and receipt
  over MoQ/QUIC; subscribers choose the start chunk or specific objects.
- **Player** (`holochain_music/`, `music_catalogue/`, `holochain_storage/`): the
  only place keys are unwrapped and audio is decrypted, chunk by chunk, into a
  bounded ALSA queue.
- **Bridge** (`music-e2e/src/bin/music_app_bridge.rs`): one authenticated
  app-websocket session to the local conductor with an allow-list of calls.

## Licence

No software licence has been chosen yet. This must be decided before release.
The bundled Holochain binaries carry their own licence terms, which must be
reviewed before redistribution.
