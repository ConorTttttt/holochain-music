"""Static regression guards for the Option B layered Now Playing UI.

Run: python3 -m unittest discover -s tests -p 'test_ui_layered_player.py' -v
These checks do not replace manual browser, speaker or screen-reader testing.
"""
import ast
from html.parser import HTMLParser
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "holochain_music" / "ui"
HTML = (UI / "index.html").read_text(encoding="utf-8")
CSS = (UI / "app.css").read_text(encoding="utf-8")
JS = (UI / "app.js").read_text(encoding="utf-8")


class Markup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = {}

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if "id" in attrs:
            if attrs["id"] in self.elements:
                raise AssertionError("duplicate id: " + attrs["id"])
            self.elements[attrs["id"]] = (tag, attrs)


class LayeredPlayerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.markup = Markup()
        cls.markup.feed(HTML)

    def test_server_python_syntax_is_valid(self):
        # A UI-only test run must still catch a broken server import.
        source = (ROOT / "holochain_music" / "server.py").read_text(encoding="utf-8")
        ast.parse(source, filename="holochain_music/server.py")

    def test_existing_persistent_player_stays_singleton(self):
        self.assertEqual(HTML.count('class="player" aria-label="Player"'), 1)
        for control in ("btn-play", "btn-back", "btn-fwd", "btn-next", "seek", "volume", "state-badge"):
            self.assertIn(control, self.markup.elements)
        self.assertIn("p.seq < lastSeq", JS)
        self.assertIn("function requestSeek(frame)", JS)
        self.assertIn("renderLayers();", JS)

    def test_panel_opens_only_on_demand_and_does_not_replace_route(self):
        tag, panel = self.markup.elements["now-panel"]
        self.assertEqual(tag, "aside")
        self.assertIn("hidden", panel)
        self.assertIn("aria-labelledby", panel)
        _, toggle = self.markup.elements["btn-now-panel"]
        self.assertEqual(toggle["aria-controls"], "now-panel")
        self.assertEqual(toggle["aria-expanded"], "false")
        self.assertIn("panel.hidden = !open", JS)
        self.assertIn("document.querySelector('.shell').classList.toggle('panel-open', open)", JS)
        self.assertIn("panel.focus()", JS)
        self.assertIn("layerOrigin.focus()", JS)
        self.assertIn("function show(name, arg = null)", JS)

    def test_right_edge_tab_opens_small_side_panel_without_resetting_audio(self):
        tag, attrs = self.markup.elements["now-edge-tab"]
        self.assertEqual(tag, "button")
        self.assertEqual(attrs["aria-controls"], "now-panel")
        self.assertEqual(attrs["aria-expanded"], "false")
        self.assertEqual(attrs["type"], "button")
        self.assertNotIn("hidden", attrs)
        self.assertIn("now-edge-tab", CSS)
        self.assertIn("position: fixed; z-index: 12; right: 0", CSS)
        self.assertIn(".now-edge-tab[hidden] { display: none; }", CSS)
        self.assertIn("position: fixed; z-index: 13; top: 12px; right: 0", CSS)
        self.assertIn("width: min(340px, calc(100vw - 28px))", CSS)
        self.assertIn("panel.hidden = !open;", JS)
        self.assertIn("$('now-edge-tab').addEventListener('click', () => setLayerPanel(true));", JS)
        self.assertIn("$('now-edge-tab').setAttribute('aria-expanded', String(open));", JS)
        self.assertIn("$('now-edge-tab').hidden = open;", JS)
        self.assertIn("layerOrigin.focus()", JS)
        self.assertIn("panel.focus()", JS)
        self.assertNotIn("new Audio(", JS)

    def test_bottom_player_surface_opens_expanded_view_without_hijacking_controls(self):
        tag, attrs = self.markup.elements["player-expand-hint"]
        self.assertEqual(tag, "span")
        self.assertIn("tabindex=\"0\"", HTML)
        self.assertIn('aria-describedby="player-expand-hint"', HTML)
        self.assertIn("const playerBar = document.querySelector('footer.player')", JS)
        self.assertIn("playerBar.addEventListener('click', event => {", JS)
        self.assertIn("if (event.target.closest(playerControlSelector)) return;", JS)
        self.assertIn('button, input, select, textarea, a, label', JS)
        self.assertIn("playerBar.addEventListener('keydown', event => {", JS)
        self.assertIn("event.target !== playerBar || event.key !== 'Enter' || event.repeat", JS)
        self.assertIn("openExpandedPlayer(playerBar)", JS)
        self.assertIn("if (dialog.open) return;", JS)
        self.assertIn("footer.player { cursor: pointer; }", CSS)

    def test_expanded_player_is_accessible_native_dialog(self):
        tag, _ = self.markup.elements["now-expanded"]
        self.assertEqual(tag, "dialog")
        self.assertIn("aria-labelledby", self.markup.elements["now-expanded"][1])
        self.assertIn("showModal()", JS)
        self.assertIn("expandedOrigin.focus()", JS)
        self.assertIn("e.key === 'Escape'", JS)
        for control in ("expanded-play", "expanded-back", "expanded-next", "expanded-seek",
                        "expanded-volume", "expanded-queue"):
            self.assertIn(control, self.markup.elements)

    def test_controls_delegate_to_existing_engine_api(self):
        for delegation in (
            "$('panel-play').addEventListener('click', () => $('btn-play').click())",
            "$('expanded-play').addEventListener('click', () => $('btn-play').click())",
            "$('expanded-back').addEventListener('click', () => $('btn-back').click())",
            "$('expanded-next').addEventListener('click', () => $('btn-next').click())",
            "$('volume').dispatchEvent(new Event('input'))",
        ):
            self.assertIn(delegation, JS)
        self.assertIn("requestSeek($('expanded-seek').value * p.total_frames / 1000)", JS)
        self.assertIn("$('expanded-seek').addEventListener('change'", JS)
        self.assertIn("$('btn-queue').addEventListener('click', () => show('queue')", JS)

    def test_layered_state_is_text_only_and_does_not_fake_source_metadata(self):
        self.assertIn("$(titleId).textContent = title", JS)
        self.assertIn("$(id).textContent = $('state-badge').textContent", JS)
        self.assertIn("state.queue.map(id =>", JS)
        self.assertIn("art.getAttribute('src')", JS)
        self.assertIn("URL.createObjectURL(image)", JS)
        self.assertNotIn("item.cover_url", JS)
        self.assertNotIn("bit-perfect", HTML.lower())

    def test_reflow_themes_and_font_remain(self):
        self.assertIn(".shell.panel-open", CSS)
        self.assertIn("@media (max-width: 1100px)", CSS)
        self.assertIn("@media (max-width: 860px)", CSS)
        self.assertIn("@media (max-width: 420px)", CSS)
        self.assertIn("prefers-reduced-motion: reduce", CSS)
        for token in ("--panel", "--panel-2", "--text", "--accent", "--line"):
            self.assertIn("var(" + token + ")", CSS)
        self.assertIn('"Inter"', CSS)
        self.assertIn("#ph-vinyl-record", HTML)
        self.assertIn("#ph-pause-fill", JS)


if __name__ == "__main__":
    unittest.main()
