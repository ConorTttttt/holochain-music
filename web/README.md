# web/ — experimental Holochain Music browser client

Not released. See [docs/web/](../docs/web/README.md) for status, setup,
architecture, security, grants and test evidence.

```
src/security/      v1 crypto (WebCrypto only), canonical JSON, strict encoders
src/adapters/      holochain (HWC), catalogue + trust resolution, media adapter client, grants
src/player/        WAV rules, streaming player, AudioWorklet
src/app/main.js    UI (reuses the desktop app.css, fonts and icon at build time)
public/            index.html, web.css, manifest
adapter/           ciphertext-only MoQ -> HTTPS media adapter (separate service)
hwc/               pinned HWC build (Imposter patches + multi-cell routing patch), pins.json
integration/       native artist/peer runner, Chromium/HWC listener, full interop harness
tests/             vectors from native Python, Node + Chromium crypto tests, unit tests
scripts/           build.mjs, serve.mjs (dev server with the production CSP)
```
