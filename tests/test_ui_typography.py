"""Regression checks for offline typography trial. No third-party dependencies.

Run: python3 -m unittest discover -s tests -p 'test_ui_typography.py' -v
The checks are static; an interactive browser pass is still required.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "holochain_music" / "ui"
CSS = (UI / "app.css").read_text(encoding="utf-8")
JS = (UI / "app.js").read_text(encoding="utf-8")
SERVER = (ROOT / "holochain_music" / "server.py").read_text(encoding="utf-8")
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
FONTS = (
    "inter-latin-400-normal.woff2",
    "inter-latin-500-normal.woff2",
    "inter-latin-600-normal.woff2",
    "inter-latin-700-normal.woff2",
    "space-grotesk-latin-600-normal.woff2",
    "space-grotesk-latin-700-normal.woff2",
)


class UITypographyTests(unittest.TestCase):
    def test_offline_font_assets_are_woff2(self):
        for name in FONTS:
            with self.subTest(font=name):
                data = (UI / "fonts" / name).read_bytes()
                self.assertTrue(data.startswith(b"wOF2"))
                self.assertGreater(len(data), 8000)

    def test_font_licenses_bundled(self):
        for name in ("Inter-OFL.txt", "SpaceGrotesk-OFL.txt"):
            with self.subTest(license=name):
                content = (UI / "fonts" / name).read_text(encoding="utf-8")
                self.assertIn("SIL OPEN FONT LICENSE", content)
                self.assertIn("Version 1.1", content)

    def test_css_uses_same_origin_local_fonts(self):
        self.assertEqual(CSS.count("@font-face"), len(FONTS))
        for name in FONTS:
            with self.subTest(font=name):
                self.assertIn('url("/fonts/' + name + '") format("woff2")', CSS)
        self.assertIn("font-display: swap", CSS)
        self.assertNotIn("fonts.googleapis.com", CSS)
        self.assertNotIn("fonts.gstatic.com", CSS)
        self.assertNotIn("@import url(", CSS)

    def test_two_typography_styles_and_readable_hierarchy(self):
        self.assertIn('font: 15px/1.5 var(--font-ui)', CSS)
        self.assertIn(':root[data-typography="expressive"]', CSS)
        self.assertIn('--font-display: "Space Grotesk", "Inter"', CSS)
        self.assertIn('h1, h2, .brand strong { font-family: var(--font-display);', CSS)
        self.assertIn('.row .title strong, .tile strong, .now-text strong', CSS)
        self.assertIn("font-variant-numeric: tabular-nums", CSS)
        self.assertIn("system-ui", CSS)

    def test_typography_select_is_accessible_and_in_settings(self):
        self.assertIn("el('h2', { text: 'Typography' })", JS)
        self.assertIn("el('select', { id: 'typography', onchange: e => setTypography(e.target.value) }", JS)
        self.assertIn("el('label', { for: 'typography', text: 'Font style' })", JS)
        self.assertIn("el('option', { value: 'balanced'", JS)
        self.assertIn("el('option', { value: 'expressive'", JS)

    def test_typography_persists_only_in_browser(self):
        self.assertIn("const TYPOGRAPHY_KEY = 'holochain_music_typography';", JS)
        self.assertIn("localStorage.getItem(TYPOGRAPHY_KEY)", JS)
        self.assertIn("localStorage.setItem(TYPOGRAPHY_KEY, mode)", JS)
        self.assertIn("document.documentElement.setAttribute('data-typography', mode)", JS)
        self.assertIn("document.documentElement.removeAttribute('data-typography')", JS)
        self.assertIn("typography.value = getTypography()", JS)
        self.assertIn("setTypography(getTypography())", JS)

    def test_appearance_modes_still_independent(self):
        self.assertIn("setAppearance(getAppearance())", JS)
        self.assertIn("setTypography(getTypography())", JS)
        self.assertIn("const APPEARANCE_MODES = new Set(['system', 'light', 'dark', 'amethyst-night', 'amethyst-light'])", JS)
        self.assertIn('data-theme="amethyst-light"', CSS)
        self.assertIn('data-theme="amethyst-night"', CSS)
        self.assertNotIn("data-theme", JS.split("function setTypography(value) {", 1)[1].split("\n}", 1)[0])

    def test_server_only_exposes_allowlisted_font_paths(self):
        for name in FONTS:
            with self.subTest(font=name):
                route = f'"/fonts/{name}": ("fonts/{name}", "font/woff2")'
                self.assertIn(route, SERVER)
        self.assertIn("if method == \"GET\" and path.path in STATIC:", SERVER)
        self.assertIn("font-src 'self'", SERVER)

    def test_installers_include_fonts_and_licenses(self):
        self.assertIn('"ui/fonts/*.woff2"', PYPROJECT)
        self.assertIn('"ui/fonts/*.txt"', PYPROJECT)

    def test_phosphor_player_style_is_untouched(self):
        self.assertIn(".player button { width: 40px; height: 40px; border: 0; border-radius: 0; background: transparent;", CSS)
        self.assertIn(".player .primary { width: 46px; height: 46px; border-radius: 50%;", CSS)


if __name__ == "__main__":
    unittest.main()
