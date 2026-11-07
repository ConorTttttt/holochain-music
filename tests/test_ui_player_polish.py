"""No-dependency regression checks for visual player UI polish.

Run: python3 -m unittest discover -s tests -p 'test_ui_player_polish.py' -v
These are static checks; real browser and audio tests remain separate.
"""
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "holochain_music" / "ui"
HTML = (UI / "index.html").read_text(encoding="utf-8")
CSS = (UI / "app.css").read_text(encoding="utf-8")
JS = (UI / "app.js").read_text(encoding="utf-8")
SERVER = (ROOT / "holochain_music" / "server.py").read_text(encoding="utf-8")
PREVIEW_HTML = (UI / "player-preview.html").read_text(encoding="utf-8")
PREVIEW_CSS = (UI / "player-preview.css").read_text(encoding="utf-8")
PREVIEW_JS = (UI / "player-preview.js").read_text(encoding="utf-8")


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = {}
        self.footers = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if a.get("id"):
            self.ids[a["id"]] = (tag, a)
        if tag == "footer":
            self.footers.append(a)


class PlayerPolishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elements = Elements()
        cls.elements.feed(HTML)

    def test_all_existing_transport_ids_and_labels_remain(self):
        for name, label in (
            ("btn-stop", "Stop"), ("btn-back", "Back 10 seconds"),
            ("btn-play", "Play"), ("btn-fwd", "Forward 10 seconds"),
            ("btn-next", "Next in queue"), ("btn-queue", "Show queue"),
        ):
            with self.subTest(button=name):
                tag, attrs = self.elements.ids[name]
                self.assertEqual(tag, "button")
                self.assertEqual(attrs.get("aria-label"), label)
                self.assertEqual(attrs.get("type"), "button")
        for name in ("elapsed", "duration", "now-title", "now-artist", "state-badge", "seek", "volume"):
            self.assertIn(name, self.elements.ids)

    def test_fallback_vinyl_is_decorative_and_not_remote_art(self):
        self.assertIn('<div class="art" aria-hidden="true" title="Artwork placeholder">', HTML)
        self.assertIn('<use href="#ph-vinyl-record"></use>', HTML)
        self.assertIn(".player .art {", CSS)
        self.assertIn(".player .art::before {", CSS)
        self.assertNotIn("cover_url", JS)
        self.assertNotIn('src="https://', PREVIEW_HTML)

    def test_player_uses_existing_theme_tokens_and_unchanged_play_button_shape(self):
        for token in ("--panel", "--panel-2", "--text", "--muted", "--accent", "--line", "--focus"):
            self.assertIn("var(" + token + ")", CSS)
        self.assertIn(".player .primary { width: 46px; height: 46px; border-radius: 50%;", CSS)
        self.assertIn(".player button { width: 40px; height: 40px; border: 0; border-radius: 0; background: transparent;", CSS)

    def test_progress_bar_uses_accessible_real_range_control(self):
        seek_tag, attrs = self.elements.ids["seek"]
        self.assertEqual(seek_tag, "input")
        self.assertEqual(attrs["type"], "range")
        self.assertEqual(attrs["aria-label"], "Playback position")
        self.assertEqual(attrs["max"], "1000")
        self.assertIn("#seek::-webkit-slider-runnable-track", CSS)
        self.assertIn("#seek::-moz-range-progress", CSS)
        self.assertIn("#seek:focus-visible", CSS)
        self.assertIn("var(--seek-progress, 0%)", CSS)

    def test_progress_fill_updates_only_presentation_on_drag(self):
        self.assertIn("function paintSeekProgress()", JS)
        self.assertIn("slider.style.setProperty('--seek-progress'", JS)
        self.assertIn("$('seek').addEventListener('input', paintSeekProgress)", JS)
        self.assertIn("if (!dragging) $('seek').value =", JS)
        self.assertIn("  paintSeekProgress();", JS)
        # The original seek submission still happens on change, not input.
        self.assertIn("$('seek').addEventListener('change', () => { dragging = false;", JS)
        self.assertNotIn("addEventListener('input', requestSeek", JS)

    def test_player_metadata_and_status_remain_text_only(self):
        self.assertIn("$('now-title').textContent = title;", JS)
        self.assertIn("$('now-artist').textContent = artist;", JS)
        self.assertIn("$('now-title').title = title;", JS)
        self.assertIn("$('now-artist').title = artist;", JS)
        self.assertIn("badge.textContent", JS)
        self.assertIn("badge.title = badge.textContent", JS)
        self.assertNotIn("$('now-title').innerHTML", JS)

    def test_no_playback_api_routes_or_key_controls_changed(self):
        for route in ("/api/play", "/api/pause", "/api/resume", "/api/seek", "/api/stop", "/api/next", "/api/volume"):
            self.assertIn(route, JS)
        self.assertIn("playing ? '#ph-pause-fill' : '#ph-play-fill'", JS)
        self.assertIn("pendingSeek", JS)
        self.assertIn("p.seq < lastSeq", JS)
        self.assertIn("$('btn-queue').addEventListener('click', () => show('queue')", JS)

    def test_mobile_layout_keeps_player_controls(self):
        self.assertIn("grid-template-areas: \"now\" \"transport\" \"side\"", CSS)
        self.assertIn("@media (max-width: 860px)", CSS)
        self.assertIn("@media (max-width: 420px)", CSS)
        self.assertIn(".player .volume input", CSS)
        self.assertNotIn(".player .side { display: none", CSS)

    def test_all_existing_colours_and_inter_remain(self):
        for theme in ("light", "amethyst-light", "amethyst-night"):
            self.assertIn('data-theme="' + theme + '"', CSS)
        self.assertIn('#0D1820', CSS)
        self.assertIn('font: 15px/1.5 var(--font-ui)', CSS)
        self.assertIn('"Inter"', CSS)

    def test_backend_free_preview_reuses_player_markup(self):
        self.assertIn('href="/app.css"', PREVIEW_HTML)
        self.assertIn('href="/player-preview.css"', PREVIEW_HTML)
        self.assertIn('src="/player-preview.js"', PREVIEW_HTML)
        self.assertIn('class="player" aria-label="Player interface sample" inert', PREVIEW_HTML)
        self.assertIn('id="seek"', PREVIEW_HTML)
        self.assertIn('style="--seek-progress: 32.4%"', PREVIEW_HTML)
        self.assertIn("Demo artist", PREVIEW_HTML)
        self.assertIn("Amethyst Night", PREVIEW_HTML)
        self.assertIn("Ocean Signal Light", PREVIEW_HTML)
        self.assertIn("pointer-events: none", PREVIEW_CSS)
        self.assertNotIn("/api/", PREVIEW_JS)
        self.assertNotIn("localStorage", PREVIEW_JS)
        self.assertNotIn('"/player-preview.html":', SERVER)


if __name__ == "__main__":
    unittest.main()
