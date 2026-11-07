# v1.0.0-rc1 checksums (release candidate — not a release)

Built 2026-11-06T12:37Z from commit `958b23d` with `packaging/build-deb.sh --skip-build`.
This build **supersedes** the earlier rc1 build `1e24f783…0f24`; it adds the seek fix (`852d0b7`).
A second assembly from the same inputs produced the identical SHA-256.

```
5462eacfba8af0300fd3cf50db24df6b092235c99e842b856badb87a204467eb  holochain-music_1.0.0~rc1_amd64.deb
```

## Bundled executables and hApp

```
bc657cb70eaf0fe8e4a4423e437d0a0f5b45a450ba04a6695ac67c2a98843b0a  usr/bin/holochain-music
60cd5270ed09a2599f76fac712d431ddc2092f0cf7979b1a91f603b8d1cfec3a  usr/lib/holochain-music/bin/hc
fb99eff96b0bc32a235b8891d69c6869d881d205b5176b8e8dfbbb74f6d3b54f  usr/lib/holochain-music/bin/holochain
793a3d83fb504aebe66d36f0d096ad2f93caffeb635c9f1200638f94b2075da9  usr/lib/holochain-music/bin/holochain-music-moq
2b94a16043745b38e5f658fbc56f4fbc34b27f2e4fc25e3ea13141af373baa51  usr/lib/holochain-music/bin/kitsune2-bootstrap-srv
732ae78b354be574d94d5f2e71d83f220e53d44fd59ba3f1d683740b5de2e370  usr/lib/holochain-music/bin/music_app_bridge
9ec4c6efc5e449e6e6977a86728870301d4bfdf69a1d0b3b397cfa226dab753d  usr/lib/holochain-music/holochain_music.happ
```

## Final installed-package smoke test (extracted .deb, system Python, clean environment)

```
ok  both instances online
ok  artist published f2275e029398
ok  listener discovered track (18s)
ok  playback refused without a grant
ok  private licence received
ok  streamed to the end (first audio 326 ms)
ok  download complete, offline ready
ok  offline playback with no network services started
PASS in 41s
```
