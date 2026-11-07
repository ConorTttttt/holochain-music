"""I1 static design-system migration guards; not browser/accessibility test results."""
from pathlib import Path
import re
import unittest

CSS = (Path(__file__).resolve().parents[1] / "holochain_music" / "ui" / "app.css").read_text(
    encoding="utf-8"
)
DARK, LIGHT = CSS.split("@media (prefers-color-scheme: light)", 1)


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

    def test_no_remote_font_or_stylesheet_dependency(self):
        self.assertNotIn("@import", CSS)
        self.assertNotRegex(CSS, r"url\(\s*['\"]?https?://")
        self.assertIn("Plus Jakarta Sans remains an approved future bundled-font", CSS)


if __name__ == "__main__":
    unittest.main()
