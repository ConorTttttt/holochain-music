# Changelog

## 1.0.0-rc1 (unreleased)

Builds on milestones S1–S18 (draft PRs #5–#22).

### Added
- `holochain-music` application: launcher (`start`, `--offline`, `backup`,
  `status`, `bootstrap-server`, `export`), managed Holochain conductor, local
  browser UI for listening and artist publishing.
- Long-running MoQ host (`holochain-music-moq serve`/`fetch`/`fetch-document`):
  many files and sessions, stable 0600 certificate, subscriber-chosen start
  index or object sets, signed manifest and receipt served alongside ciphertext,
  upload-rate limit.
- Perpetual personal-use licence (`holochain-music/personal-licence/v1`).
- Private access-request and grant delivery by remote call into private
  source-chain entries.
- Download manager with seek priority, bounded retries across hosts and an
  explicit `unavailable` state; playback metrics.
- Passphrase-encrypted backups; WAV export under a licence.
- Reproducible `.deb` build and a black-box installed-package smoke test.

### Changed
- Storage DNA accepts literal RFC1918 MoQ endpoints. Before this, LAN hosts
  could not publish their endpoint at all.
- Catalogue DNA: bounded `browse_tracks`.
- Zome lockfiles pinned to Holochain 0.7.0 type crates.

### Removed
- Public listener-to-track grant, request and listener-key entries. They were
  introduced earlier on this branch and never released.

### Security
- Conductor admin WebSocket restricted to the bridge Origin. Before this, any
  web page could open it.
- MoQ TLS key written 0600 in a 0700 directory.
