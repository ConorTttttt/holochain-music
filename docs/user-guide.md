# Holochain Music — user guide (v1.0.0 release candidate)

## Start the app

Run `holochain-music` (or open **Holochain Music** from the applications menu).
A terminal shows a private `http://127.0.0.1:…/#token=…` link, and your browser
opens it. Only use that link on this computer and don't share it. Close the app
with Ctrl+C in the terminal.

The first start creates your Holochain identity and installs the app; this takes
about a minute. The status under the logo shows **Online · Holochain** or
**Offline**.

## Listening

1. **Browse**, **Artists** or the search box (press `/`) list what artists have
   published. New computers can take a few minutes to see the network; we have
   measured anywhere from seconds to about five minutes.
2. A track you have no access to shows **No access**. Choose
   **Request streaming** (24-hour access) or **Request licence** (permanent
   personal use, offline playback and export). Your request goes privately to
   the artist's computer, which must be online at that moment. If it isn't, try
   again later.
3. When the artist approves, the grant arrives privately and the track becomes
   playable. The app checks for new grants every 15 seconds.
4. **Play** streams the encrypted track from the artist's host. The badge in the
   player shows **Streaming**, **Buffering…**, **Playing · offline copy**,
   **Paused** or **Error**.
5. Controls: Space play/pause, ←/→ 10 seconds, ↑/↓ volume, N next in queue.
   Seeking starts a new verified session at that point (expect a short gap).
6. **Download** stores the encrypted track on this computer. With a licence, the
   track shows **Offline ready** and plays with no network at all:
   `holochain-music start --offline`.
7. **Export WAV** (licence only) writes a normal playable WAV into your home
   folder. That copy is ordinary unprotected audio and cannot be revoked. Your
   licence covers personal use only.
8. Use **Queue**, **Playlists** and **Recently played** to organise listening.

## Publishing (artist studio)

1. **Publish a track → Your profile**: set the artist name listeners will see.
2. Choose a 16-bit PCM WAV (mono or stereo, 8–48 kHz), give it a title and
   declare your rights. The file is encrypted on this computer. Only ciphertext
   is hosted, and the content key stays in your key store.
3. While the app is running, this computer hosts your tracks over pinned
   MoQ/QUIC. Listeners can only play after you approve them.
4. **Access requests**: grant **24 h streaming** or a **licence**. A licence is
   permanent and cannot be withdrawn.

Not supported in v1: payments, FLAC/MP3 input, publishing to a remote host,
key rotation.

## Appearance

In **Identity & settings → Appearance**, choose:

- **System (follow device)** — automatically uses the operating system's light/dark preference, including later changes.
- **Light** — always use the Ocean Signal light theme.
- **Dark** — always use the Ocean Signal dark theme.
- **Amethyst Night** — a dark violet alternative with lavender accents.
- **Amethyst Light** — a pale lavender alternative with rich-purple accents.

Changes are immediate and do **not** restart playback, Holochain, or your audio output. The preference is stored locally **in this browser** (not in the Holochain identity or encrypted backups); another browser or profile may use a different choice. If browser storage is blocked, the choice applies for the current page but may not persist. The Ocean Signal brand palette remains adjustable separately from this appearance setting.

## Back up your identity and music

Without a backup, losing this computer means losing your licences and, if you
are an artist, the ability to grant access to your own tracks.

```bash
holochain-music backup export ~/holochain-music-backup.hmb   # asks for a passphrase (≥ 10 characters)
holochain-music backup import ~/holochain-music-backup.hmb   # restores into an empty data directory only
```

The backup holds your keys, library (encrypted audio and grants) and hosted
releases, encrypted with your passphrase. Store it somewhere other than this
computer. Your Holochain agent itself lives in the conductor keystore and is not
in the backup: after a restore you get a new agent identity, but your licences
and downloaded music keep working offline.

## Troubleshooting

| Symptom | What to do |
|---|---|
| "Session token missing" | Open the exact link printed in the terminal. |
| "already running" | Another copy is open for the same data directory. |
| Status **Offline: …** | See `~/.local/share/holochain-music/logs/` (conductor, bridge, bootstrap logs). |
| Catalogue empty | Usually seconds; occasionally minutes after a peer connection drops (see release readiness). Check both computers use the same bootstrap/relay URL. To capture diagnostics start with `RUST_LOG="warn,kitsune2_core=debug,holochain_p2p=debug" holochain-music start` and keep `logs/conductor.log`. |
| "recipient unreachable" | The artist (or listener) is offline; retry later. |
| Track **Unavailable** | No host answered after 6 attempts; press Play to retry. Downloaded chunks are kept. |
| No sound | Linux: check `aplay -l` and that `alsa-utils` is installed. Windows: `holochain-music.exe audio-devices`, then set `audio_device` (see `windows-installation.md` §7). The null backend is silent by design. |
| Data directory path too long | Set `HOLOCHAIN_MUSIC_HOME` to a shorter directory. |
