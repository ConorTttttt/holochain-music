"""Ocean Signal *trial* theme regression tests (no third-party dependencies).

Run from the repository root:
  python3 -m unittest discover -s tests -p test_ui_ocean_signal.py -v

These checks validate selected colour pairings, not a full WCAG audit.
"""
from pathlib import Path
import re
import unittest


CSS = (Path(__file__).resolve().parents[1] / "holochain_music" / "ui" / "app.css").read_text(encoding="utf-8")
JS = (Path(__file__).resolve().parents[1] / "holochain_music" / "ui" / "app.js").read_text(encoding="utf-8")


def tokens(body):
    return dict(re.findall(r"--([\w-]+)\s*:\s*(#[0-9A-Fa-f]{6})\s*;", body))


def themes():
    dark = re.search(r":root\s*\{([^{}]*)\}", CSS, re.S)
    light = re.search(r"@media\s*\(prefers-color-scheme:\s*light\)\s*\{\s*:root:not\(\[data-theme\]\)\s*\{([^{}]*)\}", CSS, re.S)
    explicit_light = re.search(r':root\[data-theme="light"\]\s*\{([^{}]*)\}', CSS, re.S)
    if not dark or not light or not explicit_light:
        raise AssertionError("Dark, system light and explicit light token blocks are required")
    if tokens(light.group(1)) != tokens(explicit_light.group(1)):
        raise AssertionError("Explicit Light must match the System light palette")
    return tokens(dark.group(1)), tokens(light.group(1))


def luminance(color):
    rgb = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in rgb]
    return sum(v * w for v, w in zip(linear, (0.2126, 0.7152, 0.0722)))


def contrast(a, b):
    high, low = sorted((luminance(a), luminance(b)), reverse=True)
    return (high + 0.05) / (low + 0.05)


class OceanSignalThemeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dark, cls.light = themes()

    def test_palette_stays_provisional(self):
        self.assertIn("exploratory colour trial, not final brand approval", CSS)

    def test_dark_follows_ocean_signal_reference(self):
        self.assertEqual(self.dark["bg"], "#0D1820")
        self.assertEqual(self.dark["accent"], "#93BEFF")
        self.assertEqual(self.dark["teal"], "#75E3DC")
        self.assertIn("color-scheme: dark", CSS)

    def test_light_follows_ocean_signal_reference(self):
        self.assertEqual(self.light["bg"], "#F5FAFC")
        self.assertEqual(self.light["accent"], "#1959B8")
        self.assertEqual(self.light["panel"], "#FFFFFF")
        self.assertIn("color-scheme: light", CSS)

    def test_text_and_button_contrast_aa(self):
        for mode, theme in (("dark", self.dark), ("light", self.light)):
            for fg, bg in (
                ("text", "bg"), ("text", "panel"), ("text", "panel-2"),
                ("muted", "bg"), ("muted", "panel"), ("muted", "panel-2"),
                ("accent", "bg"), ("accent-ink", "accent"),
                ("teal", "panel"), ("teal", "panel-2"),
                ("warn", "panel-2"), ("bad", "panel-2"),
            ):
                with self.subTest(mode=mode, foreground=fg, background=bg):
                    self.assertGreaterEqual(contrast(theme[fg], theme[bg]), 4.5)

    def test_form_boundaries_and_focus_contrast(self):
        for mode, theme in (("dark", self.dark), ("light", self.light)):
            for base in ("panel", "panel-2"):
                with self.subTest(mode=mode, surface=base):
                    self.assertGreaterEqual(contrast(theme["field-border"], theme[base]), 3)
                    self.assertGreaterEqual(contrast(theme["focus"], theme[base]), 3)
        self.assertIn("border: 1px solid var(--field-border)", CSS)

    def test_ocean_signal_tokens_used_by_components(self):
        self.assertIn(".badge.ok { color: var(--teal); border-color: var(--teal); }", CSS)
        self.assertIn(".btn.primary, .player .primary { background: var(--accent);", CSS)
        self.assertIn("accent-color: var(--accent)", CSS)

    def test_theme_appearance_is_selectable_in_settings(self):
        self.assertIn("el('h2', { text: 'Appearance' })", JS)
        self.assertIn("el('label', { for: 'appearance', text: 'Theme' })", JS)
        for value in ("system", "light", "dark"):
            self.assertIn("el('option', { value: '" + value + "'", JS)
        self.assertIn("onchange: e => setAppearance(e.target.value)", JS)

    def test_theme_persists_only_in_browser_and_has_no_backend_request(self):
        self.assertIn("const APPEARANCE_KEY = 'holochain_music_appearance'", JS)
        self.assertIn("localStorage.getItem(APPEARANCE_KEY)", JS)
        self.assertIn("localStorage.setItem(APPEARANCE_KEY, mode)", JS)
        self.assertIn("document.documentElement.removeAttribute('data-theme')", JS)
        self.assertIn("document.documentElement.setAttribute('data-theme', mode)", JS)
        self.assertIn("catch (_) { return 'system'; }", JS)

    def test_system_theme_changes_with_device_and_explicit_dark_overrides_light_os(self):
        self.assertIn(":root:not([data-theme])", CSS)
        self.assertIn(':root[data-theme="light"]', CSS)
        self.assertIn("color-scheme: dark", CSS)
        self.assertIn("color-scheme: light", CSS)

    def test_preserves_borderless_icons_and_round_play_pause(self):
        self.assertIn(".player button { width: 40px; height: 40px; border: 0; border-radius: 0; background: transparent;", CSS)
        self.assertIn(".player .primary { width: 46px; height: 46px; border-radius: 50%;", CSS)
        self.assertIn(":focus-visible { outline: 3px solid var(--focus);", CSS)


if __name__ == "__main__":
    unittest.main()
