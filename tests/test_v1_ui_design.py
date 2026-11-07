"""I1 static design-system migration guards; not browser/accessibility test results."""
from pathlib import Path
import re
import unittest
import html.parser

CSS = (Path(__file__).resolve().parents[1] / "holochain_music" / "ui" / "app.css").read_text(
    encoding="utf-8"
)
DARK, LIGHT = CSS.split("@media (prefers-color-scheme: light)", 1)
UI_DIR = Path(__file__).resolve().parents[1] / "holochain_music" / "ui"
HTML = (UI_DIR / "index.html").read_text(encoding="utf-8")
JS = (UI_DIR / "app.js").read_text(encoding="utf-8")


class UiDesignTokenTests(unittest.TestCase):
    def test_appearance_roles_exist_in_both_themes(self):
        roles = (
            "color-bg-app", "color-bg-surface", "color-bg-raised",
            "color-border-decorative", "color-border-control",
            "color-text-primary", "color-text-secondary",
            "color-action-primary-bg", "color-action-primary-fg",
            "color-status-warning", "color-status-error", "color-focus-ring",
        )
        for role in roles:
            declaration = rf"--{re.escape(role)}\s*:"
            with self.subTest(role=role, theme="dark"):
                self.assertRegex(DARK, declaration)
            with self.subTest(role=role, theme="light"):
                self.assertRegex(LIGHT.split("\n}\n", 1)[0], declaration)

    def test_legacy_tokens_are_role_aliases(self):
        aliases = {
            "bg": "color-bg-app",
            "panel": "color-bg-surface",
            "panel-2": "color-bg-raised",
            "line": "color-border-decorative",
            "border-control": "color-border-control",
            "text": "color-text-primary",
            "muted": "color-text-secondary",
            "accent": "color-action-primary-bg",
            "accent-ink": "color-action-primary-fg",
            "focus": "color-focus-ring",
        }
        for legacy, role in aliases.items():
            with self.subTest(legacy=legacy):
                self.assertIn(f"--{legacy}: var(--{role});", DARK)

    def test_controls_have_shared_sizes_and_shapes(self):
        for declaration in (
            "--radius-pill: 9999px;",
            "--control-height: 40px;",
            "--control-icon-hit: 44px;",
            "--control-play-size: 52px;",
            "min-height: var(--control-height);",
            "border-radius: var(--radius-pill);",
            "width: var(--control-icon-hit); height: var(--control-icon-hit);",
            "width: var(--control-play-size); height: var(--control-play-size);",
        ):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, CSS)
        self.assertIn(":focus-visible { outline: 3px solid var(--focus);", CSS)

    def test_compact_navigation_groups_do_not_stretch_active_pill(self):
        # Regression from Ubuntu high-zoom/compact screencast: the row-style
        # sidebar stretched the active nav pill and left large vertical gaps.
        compact = CSS.split("@media (max-width: 860px)", 1)[1]
        self.assertIn(".sidebar { flex-direction: column; align-items: stretch;", compact)
        self.assertIn(".sidebar nav { display: flex; flex-wrap: wrap; align-content: flex-start;", compact)
        self.assertIn("align-items: center; gap: 4px; width: 100%;", compact)
        self.assertIn(".sidebar .nav { flex: 0 0 auto; align-self: flex-start;", compact)
        self.assertNotIn(".sidebar { flex-direction: row; flex-wrap: wrap;", compact)

    def test_compact_shell_gives_navigation_content_height(self):
        # At high zoom the two implicit auto grid rows split spare height,
        # creating a large empty block below the stacked navigation.
        compact = CSS.split("@media (max-width: 860px)", 1)[1]
        self.assertIn(
            ".shell { grid-template-columns: minmax(0, 1fr); grid-template-rows: max-content auto; }",
            compact,
        )

    def test_font_face_is_local_and_typography_is_semantic(self):
        for path in (
            "/fonts/PlusJakartaSans-wght.ttf",
            "/fonts/PlusJakartaSans-Italic-wght.ttf",
        ):
            self.assertIn(f'url("{path}")', CSS)
        self.assertEqual(CSS.count('font-family: "Plus Jakarta Sans";'), 2)
        self.assertIn("--type-size-body: 15px;", CSS)
        self.assertIn("--type-leading-body: 1.5;", CSS)
        self.assertIn("--type-weight-semibold: 600;", CSS)
        self.assertIn("font-size: var(--type-size-title);", CSS)
        self.assertIn("font-size: var(--type-size-section);", CSS)

    def test_compact_search_and_volume_fit_available_width(self):
        # At high zoom the search field and volume thumb reached the right edge
        # of the user's screenshot. Flex/grid min-content sizing must shrink.
        compact = CSS.split("@media (max-width: 860px)", 1)[1]
        for rule in (
            ".shell { grid-template-columns: minmax(0, 1fr); grid-template-rows: max-content auto; }",
            ".main { min-width: 0;",
            ".topbar { min-width: 0;",
            ".search { flex: 1 1 200px; min-width: 0; max-width: 100%; }",
            ".search input { display: block; width: 100%; max-width: 100%; min-width: 0; }",
            ".player { grid-template-columns: minmax(0, 1fr); min-width: 0;",
            ".timeline { min-width: 0; grid-template-columns: 44px minmax(0, 1fr) 44px; }",
            ".side { min-width: 0; justify-content: space-between; flex-wrap: wrap; }",
            ".volume input { width: min(100px, 25vw); min-width: 0; }",
        ):
            with self.subTest(rule=rule):
                self.assertIn(rule, compact)

    def test_theme_override_and_native_select_contract(self):
        self.assertIn('<label for="appearance">Appearance</label>', HTML)
        self.assertIn('<select id="appearance" name="appearance">', HTML)
        for mode in ("system", "light", "dark"):
            self.assertIn(f'<option value="{mode}">', HTML)
        self.assertIn(':root:not([data-theme])', CSS)
        self.assertIn(':root[data-theme="light"]', CSS)
        self.assertIn('color-scheme: dark;', CSS)
        self.assertIn('color-scheme: light;', CSS)
        self.assertIn("document.documentElement.removeAttribute('data-theme')", JS)
        self.assertIn("document.documentElement.setAttribute('data-theme', chosen)", JS)
        self.assertIn("localStorage.getItem(appearanceKey)", JS)
        self.assertIn("localStorage.setItem(appearanceKey, chosen)", JS)
        self.assertIn("['system', 'light', 'dark'].includes(mode)", JS)
        self.assertNotIn('localStorage.setItem(\'hm_token\'', JS)

    def test_no_remote_font_or_stylesheet_dependency(self):
        self.assertNotIn("@import", CSS)
        self.assertNotRegex(CSS, r"url\(\s*['\"]?https?://")
        self.assertIn('--font-ui: "Plus Jakarta Sans", system-ui,', CSS)


if __name__ == "__main__":
    unittest.main()
