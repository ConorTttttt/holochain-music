# Changelog

## Windows port (unreleased, branch `feat/v1-windows-port`)

### Added
- `holochain_storage/portable.py`: one OS layer for private dirs/keys
  (POSIX modes / Windows protected DACLs), single-instance lock, child-process
  supervision (console-less, Job Object), timed pipe reads (`select` or a
  bounded reader thread), retrying atomic replace, per-user data dirs
  (XDG / `%LOCALAPPDATA%\HolochainMusic`).
- Windows audio backend `wasapi` (`music_catalogue/audio_output.py`): PortAudio
  WASAPI shared mode, bounded 200 ms ring, immediate abort, MME fallback,
  device selection; `holochain-music audio-devices`.
- `holochain-music open` / `quit` and `POST /api/shutdown` (token-protected), so
  a console-less app can be reopened and stopped. Launching again reopens the
  running instance's page.
- Windows packaging: `packaging/windows/` (NSIS installer, C launchers,
  icon generator, pinned inputs, licence notices),
  `HolochainMusic-1.0.0-rc-windows-x64.exe` (unsigned, private testing).
- CI: `.github/workflows/windows.yml` (Windows Rust/Python tests, real
  conductor e2e on one runner, installer build, silent install/smoke/uninstall).
- Docs: `docs/windows-installation.md`, `docs/windows-lan-test-plan.md`.

### Changed
- Binary lookup understands `.exe` and the installed `<root>/{python,bin}` layout.
- Text files are read and written as UTF-8 explicitly.
- Permission assertions in tests are platform-aware (`v1_fixtures.assert_private`).
- Linux behaviour is unchanged (same ALSA backend, same `select`-based reads,
  same modes, same paths).

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
- Store-and-retry outbox for private requests and grants; requests can be sent
  while the artist and host are offline.
- `holochain-music config show|set`.
- Bootstrap poll interval capped at 30 s by default (kitsune2's default
  doubles to 5 minutes and never resets).

### Changed
- Storage DNA accepts literal RFC1918 MoQ endpoints. Before this, LAN hosts
  could not publish their endpoint at all.
- Catalogue DNA: bounded `browse_tracks`.
- Zome lockfiles pinned to Holochain 0.7.0 type crates.

### Removed
- Public listener-to-track grant, request and listener-key entries. They were
  introduced earlier on this branch and never released.

### Security
- Private inbox: windowed rate limits instead of a lifetime cap (which allowed
  permanent denial of service); recipient-chosen nonce in request entries;
  remote refusals distinguished from an offline recipient.
- Conductor admin WebSocket restricted to the bridge Origin. Before this, any
  web page could open it.
- MoQ TLS key written 0600 in a 0700 directory.
