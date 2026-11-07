"""Static regression checks for self-hosted Inter typography and its preview.

Run: python3 -m unittest discover -s tests -p 'test_ui_typography.py' -v
An interactive browser check and packaged-app test are still required.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "holochain_music" / "ui"
CSS = (UI / "app.css").read_text(encoding="utf-8")
JS = (UI / "app.js").read_text(encoding="utf-8")
SERVER = (ROOT / "holochain_music" / "server.py").read_text(encoding="utf-8")
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
PREVIEW_HTML = (UI / "typography-preview.html").read_text(encoding="utf-8")
PREVIEW_CSS = (UI / "typography-preview.css").read_text(encoding="utf-8")
PREVIEW_JS = (UI / "typography-preview.js").read_text(encoding="utf-8")
FONTS = (
    "inter-latin-400-normal.woff2",
    "inter-latin-500-normal.woff2",
    "inter-latin-600-normal.woff2",
    "inter-latin-700-normal.woff2",
)


class UITypographyTests(unittest.TestCase):
    def test_offline_font_assets_are_woff2(self):
        for name in FONTS:
            with self.subTest(font=name):
                data = (UI / "fonts" / name).read_bytes()
                self.assertTrue(data.startswith(b"wOF2"))
                self.assertGreater(len(data), 8000)

    def test_inter_license_bundled(self):
        content = (UI / "fonts" / "Inter-OFL.txt").read_text(encoding="utf-8")
        self.assertIn("SIL OPEN FONT LICENSE", content)
        self.assertIn("Version 1.1", content)
        self.assertFalse((UI / "fonts" / "SpaceGrotesk-OFL.txt").exists())

    def test_css_uses_self_hosted_inter_only(self):
        self.assertEqual(CSS.count("@font-face"), len(FONTS))
        for name in FONTS:
            with self.subTest(font=name):
                self.assertIn('url("/fonts/' + name + '") format("woff2")', CSS)
        self.assertIn("font-display: swap", CSS)
        self.assertIn('"Inter", system-ui', CSS)
        self.assertNotIn("Space Grotesk", CSS)
        self.assertNotIn("fonts.googleapis.com", CSS)
        self.assertNotIn("fonts.gstatic.com", CSS)
        self.assertNotIn("@import url(", CSS)

    def test_inter_typography_hierarchy(self):
        self.assertIn("font: 15px/1.5 var(--font-ui)", CSS)
        self.assertIn("h1, h2, .brand strong { font-family: var(--font-display);", CSS)
        self.assertIn(".row .title strong, .tile strong, .now-text strong", CSS)
        self.assertIn("font-variant-numeric: tabular-nums", CSS)
        self.assertIn("system-ui", CSS)
        self.assertNotIn('data-typography="expressive"', CSS)

    def test_appearance_settings_remain_without_font_switcher(self):
        self.assertIn("el('h2', { text: 'Appearance' })", JS)
        self.assertIn("setAppearance(getAppearance())", JS)
        self.assertIn("const APPEARANCE_MODES = new Set(['system', 'light', 'dark', 'amethyst-night', 'amethyst-light'])", JS)
        self.assertNotIn("TYPOGRAPHY_MODES", JS)
        self.assertNotIn("data-typography", JS)
        self.assertNotIn("el('h2', { text: 'Typography' })", JS)
        self.assertIn('data-theme="amethyst-light"', CSS)
        self.assertIn('data-theme="amethyst-night"', CSS)

    def test_server_only_exposes_allowlisted_inter_fonts(self):
        for name in FONTS:
            with self.subTest(font=name):
                route = f'"/fonts/{name}": ("fonts/{name}", "font/woff2")'
                self.assertIn(route, SERVER)
        self.assertNotIn("/fonts/space-grotesk-", SERVER)
        self.assertIn('if method == "GET" and path.path in STATIC:', SERVER)
        self.assertIn("font-src 'self'", SERVER)

    def test_installers_include_fonts_and_license(self):
        self.assertIn('"ui/fonts/*.woff2"', PYPROJECT)
        self.assertIn('"ui/fonts/*.txt"', PYPROJECT)

    def test_preview_shows_inter_in_all_colours_without_backend(self):
        self.assertIn('href="/app.css"', PREVIEW_HTML)
        self.assertIn('href="/typography-preview.css"', PREVIEW_HTML)
        self.assertIn('src="/typography-preview.js"', PREVIEW_HTML)
        self.assertIn("Inter, throughout.", PREVIEW_HTML)
        self.assertIn("Ocean Signal Light", PREVIEW_HTML)
        self.assertIn("Ocean Signal Dark", PREVIEW_HTML)
        self.assertIn("Amethyst Light", PREVIEW_HTML)
        self.assertIn("Amethyst Night", PREVIEW_HTML)
        self.assertNotIn("Space Grotesk", PREVIEW_HTML)
        self.assertIn(".preview-comparison", PREVIEW_CSS)
        self.assertIn("data-theme", PREVIEW_JS)
        self.assertNotIn("/api/", PREVIEW_JS)
        self.assertNotIn("localStorage", PREVIEW_JS)
        self.assertNotIn('"/typography-preview.html":', SERVER)

    def test_no_unused_space_grotesk_fonts(self):
        self.assertEqual(list((UI / "fonts").glob("space-grotesk-*.woff2")), [])
        self.assertNotIn("Space Grotesk", PREVIEW_CSS)

    def test_phosphor_player_style_is_untouched(self):
        self.assertIn(".player button { width: 40px; height: 40px; border: 0; border-radius: 0; background: transparent;", CSS)
        self.assertIn(".player .primary { width: 46px; height: 46px; border-radius: 50%;", CSS)


if __name__ == "__main__":
    unittest.main()
