"""Offline font/source-integrity and packaging guards for UI Sprint I1.2.

Static checks only: they do not prove rendering or accessibility in a browser.
"""
import hashlib
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
FONT_DIR = ROOT / "holochain_music" / "ui" / "fonts"
UPSTREAM_BLOBS = {
    "PlusJakartaSans-wght.ttf": "0cb13a998ed525ba226d911b10d6c4c4f923a961",
    "PlusJakartaSans-Italic-wght.ttf": "82b042caaaf271beb9e3cbd95ba4741a3d5b8926",
}


class OfflineUiFontTests(unittest.TestCase):
    def test_official_unmodified_true_type_fonts(self):
        for name, expected_sha in UPSTREAM_BLOBS.items():
            with self.subTest(font=name):
                data = (FONT_DIR / name).read_bytes()
                self.assertGreater(len(data), 100_000)
                self.assertEqual(data[:4], bytes.fromhex("00010000"))
                git_blob = hashlib.sha1(
                    b"blob " + str(len(data)).encode() + b"\x00" + data
                ).hexdigest()
                self.assertEqual(git_blob, expected_sha)

    def test_complete_ofl_notice_present(self):
        notice = (FONT_DIR / "OFL.txt").read_text(encoding="utf-8")
        self.assertIn("Copyright 2020 The Plus Jakarta Sans Project Authors", notice)
        self.assertIn("SIL OPEN FONT LICENSE", notice)
        self.assertIn("Version 1.1", notice)

    def test_font_files_included_by_distribution_rules(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"ui/fonts/*.ttf"', pyproject)
        self.assertIn('"ui/fonts/*.txt"', pyproject)
        build_deb = (ROOT / "packaging" / "build-deb.sh").read_text(encoding="utf-8")
        self.assertIn("-path '*/ui/*'", build_deb)

    def test_loopback_only_font_allow_list_and_offline_loading(self):
        css = (ROOT / "holochain_music" / "ui" / "app.css").read_text(encoding="utf-8")
        server = (ROOT / "holochain_music" / "server.py").read_text(encoding="utf-8")
        self.assertNotIn("fonts.googleapis.com", css)
        self.assertNotIn("fonts.gstatic.com", css)
        self.assertIn("font-src 'self'", server)
        self.assertIn('if method == "GET" and path.path in STATIC:', server)
        for name in UPSTREAM_BLOBS:
            self.assertIn(f'url("/fonts/{name}")', css)
            self.assertIn(f'"/fonts/{name}"', server)


if __name__ == "__main__":
    unittest.main()
