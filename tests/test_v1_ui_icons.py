"""Sprint I1.3: Phosphor icons from a local audited SVG sprite.

These checks cover source structure and accessibility contracts. Browser SVG
rendering, focus behaviour and reflow still need human/local verification.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "holochain_music" / "ui"
SPRITE = (UI / "icons.svg").read_text(encoding="utf-8")
HTML = (UI / "index.html").read_text(encoding="utf-8")
JS = (UI / "app.js").read_text(encoding="utf-8")
CSS = (UI / "app.css").read_text(encoding="utf-8")
SVG_NS = "{http://www.w3.org/2000/svg}"

NAV_ICONS = {
    "browse": "compass",
    "artists": "users",
    "library": "music-notes",
    "playlists": "playlist",
    "history": "clock-counter-clockwise",
    "queue": "list-dashes",
    "publish": "microphone-stage",
    "requests": "handshake",
    "mytracks": "vinyl-record",
    "settings": "gear",
}
PLAYER_ICONS = {
    "btn-stop": "stop-regular",
    "btn-back": "rewind-regular",
    "btn-play": "play-fill",
    "btn-fwd": "fast-forward-regular",
    "btn-next": "skip-forward-regular",
}


class IconMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.buttons = {}
        self._button = None
        self.icon_uses = []
        self._inside_svg = False
        self.bad_icon_labels = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "button":
            self._button = attrs
            if attrs.get("id") or attrs.get("data-view"):
                self.buttons[attrs.get("id") or attrs.get("data-view")] = attrs
        if tag == "svg" and "ph-icon" in attrs.get("class", "").split():
            self._inside_svg = True
            if attrs.get("aria-hidden") != "true" or attrs.get("focusable") != "false":
                self.bad_icon_labels.append(attrs)
        if tag == "use" and self._inside_svg:
            self.icon_uses.append(attrs.get("href", ""))

    def handle_endtag(self, tag):
        if tag == "svg":
            self._inside_svg = False
        if tag == "button":
            self._button = None


class PhosphorIconTests(unittest.TestCase):
    def test_sprite_is_a_safe_local_svg_symbol_library(self):
        svg = ET.fromstring(SPRITE)
        self.assertEqual(svg.tag, SVG_NS + "svg")
        symbols = [x for x in svg if x.tag == SVG_NS + "symbol"]
        ids = [x.get("id") for x in symbols]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 30)
        for symbol in symbols:
            self.assertRegex(symbol.get("id", ""), r"^[a-z0-9-]+-(regular|fill)$")
            self.assertEqual(symbol.get("viewBox"), "0 0 256 256")
            self.assertEqual(symbol.get("fill"), "currentColor")
            self.assertTrue(list(symbol))
        self.assertNotIn("<script", SPRITE.lower())
        self.assertNotIn("<foreignObject", SPRITE)
        self.assertNotIn("<image", SPRITE.lower())
        self.assertNotIn("http:", SPRITE.replace('xmlns="http://www.w3.org/2000/svg"', ""))
        self.assertNotIn("https:", SPRITE)

    def test_navigation_icons_have_regular_and_fill_variants(self):
        ids = {x.get("id") for x in ET.fromstring(SPRITE)}
        markup = IconMarkup()
        markup.feed(HTML)
        for page, name in NAV_ICONS.items():
            with self.subTest(view=page):
                self.assertIn(name + "-regular", ids)
                self.assertIn(name + "-fill", ids)
                self.assertEqual(markup.buttons[page].get("data-icon"), name)
                self.assertIn(f"/icons.svg#{name}-regular", markup.icon_uses)
        self.assertIn("selected ? 'fill' : 'regular'", JS)
        self.assertIn("b.setAttribute('aria-current', 'page')", JS)

    def test_transport_icons_keep_button_accessibility_and_state(self):
        ids = {x.get("id") for x in ET.fromstring(SPRITE)}
        markup = IconMarkup()
        markup.feed(HTML)
        self.assertFalse(markup.bad_icon_labels)
        for button_id, icon_id in PLAYER_ICONS.items():
            with self.subTest(button=button_id):
                self.assertIn(icon_id, ids)
                self.assertIn(f"/icons.svg#{icon_id}", markup.icon_uses)
                self.assertTrue(markup.buttons[button_id].get("aria-label"))
        self.assertIn("/icons.svg#pause-fill", JS)
        self.assertIn("playing ? 'Pause' : 'Play'", JS)
        self.assertNotIn("textContent = playing ? '❚❚'", JS)
        self.assertIn('document.createElementNS(SVG_NS, \'svg\')', JS)
        self.assertNotIn("innerHTML", JS)

    def test_local_serving_and_mit_notice_packaged(self):
        notice = (UI / "PHOSPHOR-LICENSE.txt").read_text(encoding="utf-8")
        self.assertIn("MIT License", notice)
        self.assertIn("Copyright (c) 2023 Phosphor Icons", notice)
        self.assertIn("THE SOFTWARE IS PROVIDED", notice)
        app = (ROOT / "holochain_music" / "server.py").read_text(encoding="utf-8")
        self.assertIn('"/icons.svg": ("icons.svg", "image/svg+xml")', app)
        self.assertIn("img-src 'self'", app)
        py = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"ui/*.svg"', py)
        self.assertIn('"ui/*.txt"', py)
        deb = (ROOT / "packaging" / "build-deb.sh").read_text(encoding="utf-8")
        self.assertIn("-path '*/ui/*'", deb)

    def test_icons_inherit_current_colour_and_do_not_reduce_hit_area(self):
        self.assertIn(".ph-icon {", CSS)
        self.assertIn("fill: currentColor;", CSS)
        self.assertIn("pointer-events: none;", CSS)
        self.assertIn("width: var(--control-icon-hit); height: var(--control-icon-hit);", CSS)
        self.assertIn("--control-icon-hit: 44px;", CSS)


if __name__ == "__main__":
    unittest.main()
