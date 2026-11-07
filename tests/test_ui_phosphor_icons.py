"""No-dependency static smoke tests for the Phosphor icon update.

Run: python3 -m unittest discover -s tests -p test_ui_phosphor_icons.py -v
This does not replace real browser, accessibility or audio testing.
"""
from html.parser import HTMLParser
from pathlib import Path
import unittest

UI = Path(__file__).resolve().parents[1] / "holochain_music" / "ui"


class Icons(HTMLParser):
    def __init__(self):
        super().__init__()
        self.symbols = set()
        self.uses = []
        self.buttons = {}
        self.current = None
        self.nav_count = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "symbol":
            self.symbols.add(a["id"])
        elif tag == "button":
            self.current = a.get("id")
            if self.current:
                self.buttons[self.current] = {"attrs": a, "icons": []}
            if "with-icon" in (a.get("class") or "").split():
                self.nav_count += 1
        elif tag == "use":
            href = a.get("href")
            if href:
                self.uses.append(href)
                if self.current:
                    self.buttons[self.current]["icons"].append(href)

    def handle_endtag(self, tag):
        if tag == "button":
            self.current = None


class PhosphorIconsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (UI / "index.html").read_text(encoding="utf-8")
        cls.js = (UI / "app.js").read_text(encoding="utf-8")
        cls.css = (UI / "app.css").read_text(encoding="utf-8")
        cls.icons = Icons()
        cls.icons.feed(cls.html)

    def test_sprite_defines_every_used_icon(self):
        self.assertGreaterEqual(len(self.icons.symbols), 17)
        self.assertTrue(self.icons.uses)
        for href in self.icons.uses:
            self.assertTrue(href.startswith("#ph-"))
            self.assertIn(href[1:], self.icons.symbols, href)

    def test_transport_icons_have_accessible_names(self):
        expected = {
            "btn-stop": ("Stop", "stop"),
            "btn-back": ("Back 10 seconds", "rewind"),
            "btn-play": ("Play", "play-fill"),
            "btn-fwd": ("Forward 10 seconds", "fast-forward"),
            "btn-next": ("Next in queue", "skip-forward"),
            "btn-queue": ("Show queue", "queue"),
        }
        for button_id, (name, symbol) in expected.items():
            with self.subTest(button_id=button_id):
                b = self.icons.buttons[button_id]
                self.assertEqual(b["attrs"]["aria-label"], name)
                self.assertIn("#ph-" + symbol, b["icons"])

    def test_play_pause_switch_preserves_event_listener(self):
        self.assertIn("ph-pause-fill", self.icons.symbols)
        self.assertIn("playing ? '#ph-pause-fill' : '#ph-play-fill'", self.js)
        self.assertIn("btn-play').querySelector('use').setAttribute('href'", self.js)
        self.assertNotIn("btn-play').textContent", self.js)
        self.assertIn("btn-play').addEventListener('click'", self.js)

    def test_queue_button_opens_existing_queue(self):
        self.assertIn("btn-queue').addEventListener('click', () => show('queue')", self.js)

    def test_all_navigation_icons(self):
        self.assertEqual(self.icons.nav_count, 10)

    def test_bundled_and_palette_independent(self):
        self.assertIn("MIT License", self.html)
        self.assertIn("fill: currentColor", self.css)
        self.assertIn("icon-sprite", self.html)
        self.assertNotIn("https://cdn", self.html)

    def test_unsupported_controls_not_faked(self):
        for name in ("btn-shuffle", "btn-repeat", "btn-output"):
            self.assertNotIn('id="' + name + '"', self.html)


if __name__ == "__main__":
    unittest.main()
