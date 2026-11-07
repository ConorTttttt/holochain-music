# UI Sprint I1.3 — Phosphor Regular and Fill icons

**Status:** draft, unmerged, 7 November 2026. **Stacked after** UI I1 [PR #25](https://github.com/ConorTttttt/holochain-music/pull/25) and Plus Jakarta Sans [PR #28](https://github.com/ConorTttttt/holochain-music/pull/28). Base: `feat/ui-i1-2-plus-jakarta-font`.

## Implemented scope

- Official [Phosphor Icons](https://github.com/phosphor-icons/core) **Regular and Fill** SVG paths, bundled into a single same-origin `holochain_music/ui/icons.svg` sprite (35 named icon symbols: navigation, playback, volume, and music actions).
- Original official SVG icon path geometry is included without drawing changes. The original Phosphor [MIT licence](https://github.com/phosphor-icons/core/blob/main/LICENSE) is copied exactly to `holochain_music/ui/PHOSPHOR-LICENSE.txt`; preserve it in distributed builds.
- Navigation buttons have **Regular** icons by default and **Fill** icons only when selected; `aria-current=page` and readable text remain. All icons are decorative (`aria-hidden=true`, `focusable=false`); interactive elements retain accessible labels.
- Persistent transport buttons (Stop, Rewind, Play/Pause, Fast-forward, Next) use Phosphor icons. The Play/Pause `<use>` reference changes only when needed, not on every 500 ms player poll. The existing player engine, `seq` acknowledgement, pause action and button `aria-label` logic are preserved.
- Speaker/volume icon is purely presentational; Volume retains its native range input and accessible label.
- Music action buttons retain text and prepend icons via a whitelisted JS `icon(name)` factory using `document.createElementNS` (no `innerHTML`, remote catalogue input or external icon/CDN requests). No new JS framework is introduced.
- Explicit only `GET /icons.svg` added to the existing authenticated loopback server's **static asset allow-list**. Image mime `image/svg+xml`, existing `img-src 'self'`, strict host/origin and no API/secret exposure changes.
- Existing wheel package-data includes `ui/*.svg`; updated to include root `ui/*.txt` for the MIT licence. Deterministic Debian package copies the entire UI subtree.
- Static icon safety, licensing and markup/accessibility contracts in `tests/test_v1_ui_icons.py`; actual local HTTP/CSP regression in `test_v1_app_server.py`.

**Important:** The app's artwork/logo `/icon.svg` is not replaced: the Phosphor icon system is for interface controls, not branding.

## Design mapping

| Interface | Icon roles | Style |
| --- | --- | --- |
| Browse, Artists, Library, Playlists, History, Queue | Compass, Users, Music Notes, Playlist, Clock Counter-clockwise, List Dashes | Regular default, Fill selected |
| Artist Studio, Access Requests, Your Releases, Identity & Settings | Microphone Stage, Handshake, Vinyl Record, Gear | Regular default, Fill selected |
| Transport | Stop, Rewind, Play/Pause, Fast-forward, Skip Forward | Regular transport, **Fill primary Play/Pause** |
| Volume | Speaker High | Regular; input remains native |
| Track actions | Play, Queue, Download, Export, Playlist, Request Access | Regular; text labels remain |

**Colours:** Icons inherit `currentColor` from the UI. The **final brand palette remains UNDECIDED**. No change to selected Plus Jakarta Sans typography or semantic theme roles.

## Integrity and security

Source: `phosphor-icons/core` → `assets/regular/*.svg` and `assets/fill/*-fill.svg` (main branch at this implementation). The sprite uses only vetted static `path`/SVG geometry, never untrusted HTML or remote images. The project includes its required MIT notice. Future Phosphor updates should be reviewed and validated, not fetched dynamically at runtime.

**API/media boundary:** No change to user data, artist grants, payment, Holochain DNAs, MoQ transport, private session token, Python player, audio backend, or encryption. Icon-only refactors must never reset actual queue/seek state.

## Test instructions on user's Ubuntu test machine

Use a **separate checkout** to preserve current I1 and font tests:

```bash
cd ~/holochain-music-testing
git clone --depth 1 --single-branch --branch feat/ui-i1-3-phosphor-icons \
  https://github.com/ConorTttttt/holochain-music.git ui-icons
cd ui-icons
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .

mkdir -p "$HOME/hm-tmp"
export HOLOCHAIN_MUSIC_TEST_TMPDIR="$HOME/hm-tmp"

python -m unittest discover -s tests -p 'test_v1_ui_icons.py' -v
python -m unittest discover -s tests -p 'test_v1_ui_font_assets.py' -v
python -m unittest discover -s tests -p 'test_v1_ui_design.py' -v
python -m unittest discover -s tests -p 'test_v1_app_server.py' -v
node --check holochain_music/ui/app.js

export HOLOCHAIN_MUSIC_HOME="$(mktemp -d "$HOME/hm-icon-test.XXXXXX")"
python -m holochain_music.cli start --offline --audio null
```

Open the **private local** URL without sharing its session token. For an empty offline test profile, only some controls are active; compare icon shapes and selected states while switching between views and Light/Dark/System. Verify **no broken squares/empty icons** and that icons inherit active/inactive colours.

In Firefox Developer Tools Network, filter `icons.svg`: expect exactly same-origin `GET /icons.svg` **200** with Content-Type `image/svg+xml`. Inspect a specific `<use href="/icons.svg#compass-fill">` after selecting Browse. With a fresh no-library profile, Play remains disabled; a later licensed-track fixture must verify actual Play→Pause icon state, audio and accessible label updates.

At **100% and 200% browser zoom**, normal and compact layouts should retain readable text and 40–52px project hit targets without clipping. Press Tab through navigation and player; focus ring should remain visible. A screen reader should read the **button action**, not announce redundant decorative SVGs.

**Optional packaging:** Build a wheel in a home-directory temp folder (if `/tmp` quota-limited); inspect it for `ui/icons.svg`, `ui/PHOSPHOR-LICENSE.txt`, Plus Jakarta Sans fonts and OFL. Validate the `.deb` as part of release packaging separately.

## Acceptance criteria (not yet passed by opening PR)

- [ ] Structural icon/static/HTTP tests pass locally and in GitHub Actions; test evidence includes latest build SHA.
- [ ] Icon sprite served from local application without network or CSP errors.
- [ ] Visual comparison in Light/Dark, wide/compact, 200% zoom; all selected Fill states are visible.
- [ ] Play/Pause icon/aria-label synchronise with actual engine state, no extra update churn or audio changes.
- [ ] Keyboard and screen reader interaction, including no duplicate decorative icon announcements.
- [ ] Python wheel and Debian package include MIT notice and source assets.
- [ ] I1 and font PRs remain staged/verified in sequence; Windows physical speaker test is separate.
- [ ] The final brand colour palette is still deliberately **UNDECIDED**.

Related: [Iconography & Icon System (Option B)](https://app.notion.com/p/411b6c6d5c04819a84bad5be543748c6), [UI audit](https://app.notion.com/p/411b6c6d5c0481f5ad79e91d2a33976a).
