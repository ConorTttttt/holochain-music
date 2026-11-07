# UI Sprint I1.2 — Plus Jakarta Sans local typography

**Status:** draft implementation based on I1 PR #25; not merged or release-approved (7 November 2026).

## Changes

- Both real upright/italic **variable TrueType** font binaries (200–800 weights), bundled directly from Google's official `google/fonts` distribution along with the complete `OFL.txt` licence. No font files were modified.
- Local `@font-face` normal/italic declarations with `font-display: swap`, offline loading and safe system-font fallback. No CDN or external stylesheet.
- Reusable semantic typography sizes, weights and line heights applied to app headings, labels, navigation, forms, badges and player.
- Explicit Python loopback static routes for two font assets only, `font/ttf` MIME, CSP `font-src 'self'` and strict existing Host checks.
- Python packaging includes binary TTF/OFL resources; existing Debian script copies UI assets recursively.
- Font-source integrity, packaging and actual static-HTTP tests. Visual/UI, hardware and accessibility testing still open.

## Official font provenance

From [Google Fonts — Plus Jakarta Sans](https://github.com/google/fonts/tree/main/ofl/plusjakartasans). SIL Open Font License 1.1, copyright 2020 The Plus Jakarta Sans Project Authors.

| File | Git blob SHA from official Google Fonts |
| --- | --- |
| `ui/fonts/PlusJakartaSans-wght.ttf` (renamed from `PlusJakartaSans[wght].ttf`) | `0cb13a998ed525ba226d911b10d6c4c4f923a961` |
| `ui/fonts/PlusJakartaSans-Italic-wght.ttf` (renamed from `PlusJakartaSans-Italic[wght].ttf`) | `82b042caaaf271beb9e3cbd95ba4741a3d5b8926` |
| `ui/fonts/OFL.txt` | `ea69b0ca12a02556c436680ea0a159efb7a748fa` |

Keep the OFL text with every distributed build, and do not sell the fonts separately. Preserve the author's licence and avoid modifying files without a separate review.

## Safe local test procedure (Ubuntu)

Run in a **separate** checkout. Do not merge into Windows RC3 or an artist PR worktree.

```sh
cd ~/holochain-music-testing
git clone --single-branch --branch feat/ui-i1-2-plus-jakarta-font \
  https://github.com/ConorTttttt/holochain-music.git ui-font
cd ui-font
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
mkdir -p "$HOME/hm-tmp"
export HOLOCHAIN_MUSIC_TEST_TMPDIR="$HOME/hm-tmp"

python -m unittest discover -s tests -p 'test_v1_ui_font_assets.py' -v
python -m unittest discover -s tests -p 'test_v1_ui_design.py' -v
python -m unittest discover -s tests -p 'test_v1_app_server.py' -v
node --check holochain_music/ui/app.js

export HOLOCHAIN_MUSIC_HOME="$(mktemp -d "$HOME/hm-font-test.XXXXXX")"
python -m holochain_music.cli start --offline --audio null
```

The new font HTTP test should return 200/Content-Type `font/ttf`/valid TrueType header for both files, with restrictive CSP.

In the browser, verify font and app layout in Light, Dark and System at 100% and 200% zoom. In Developer Tools, inspect the **Fonts** panel or run `await document.fonts.load('400 15px "Plus Jakarta Sans"')` to trigger loading, then `document.fonts.check('400 15px "Plus Jakarta Sans"')`; ensure local font request returns HTTP 200 and no remote font requests are made.

Optional wheel check: from the branch, run `python -m pip wheel --no-deps -w "$HOME/hm-tmp/wheels" .` and inspect the wheel archive for both `*.ttf` and `OFL.txt`.

## Acceptance

- [ ] I1 PR #25 passes all eight static tests and focused keyboard/reflow checks, before merging independently.
- [ ] Latest I1.2 CI and local suites pass; font routes return authentic assets and strict CSP.
- [ ] Offline browser genuinely renders Plus Jakarta Sans; no clipping in compact/200% zoom or persistent player.
- [ ] Screen reader, keyboard-focus and appearance visual checks, plus Debian/wheel packaging evidence.
- [ ] Windows audio physical speaker tests remain a separate release blocker.
- [ ] Final brand **colour palette remains UNDECIDED**.

References: [Typography decision](https://app.notion.com/p/410b6c6d5c0481b98318f54ae757beb1), [I1 draft PR](https://github.com/ConorTttttt/holochain-music/pull/25), [Implementation audit](https://app.notion.com/p/411b6c6d5c0481f5ad79e91d2a33976a).
