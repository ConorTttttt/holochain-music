"""Collection-first local Library and playlist regression checks.

Run: python3 -m unittest discover -s tests -p 'test_ui_library_collections.py' -v
The UI checks are static; real browser interactions and audio must be tested separately.
"""
import ast
from html.parser import HTMLParser
from pathlib import Path
import tempfile
import unittest

from holochain_music.library import Library, LibraryError

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "holochain_music" / "ui" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "holochain_music" / "ui" / "app.css").read_text(encoding="utf-8")
HTML = (ROOT / "holochain_music" / "ui" / "index.html").read_text(encoding="utf-8")
SERVER = (ROOT / "holochain_music" / "server.py").read_text(encoding="utf-8")


class LibraryCollectionTests(unittest.TestCase):
    def test_python_server_import_is_syntactically_valid(self):
        ast.parse(SERVER, filename="holochain_music/server.py")
        self.assertIn('"/fonts/inter-latin-700-normal.woff2"', SERVER)

    def test_collection_filters_do_not_conflate_rights_with_downloads(self):
        self.assertIn("const libraryFilters = { scope: 'all', query: '', sort: 'default' };", JS)
        self.assertIn("track.grant_kind === 'perpetual-personal'", JS)
        self.assertIn("track.grant_kind === 'stream'", JS)
        self.assertIn("track.offline_ready === true", JS)
        self.assertIn("Boolean(track.requested) && !track.playable", JS)
        self.assertIn("not a verified purchase history", JS)
        self.assertIn("Rental and subscription payments are not yet distinguished", JS)

    def test_library_search_sort_and_filter_preserve_preference_without_playback_calls(self):
        self.assertIn("return renderLibraryView();", JS)
        self.assertIn("libraryFilters.query = search.value", JS)
        self.assertIn("libraryFilters.sort = sort.value", JS)
        self.assertIn("libraryFilters.scope = value", JS)
        self.assertIn("role: 'group'", JS)
        self.assertIn("'aria-pressed': String(value === libraryFilters.scope)", JS)
        self.assertIn("results.replaceChildren", JS)
        self.assertIn("t.album_title", JS)
        self.assertIn(".library-scope[aria-pressed=", CSS)
        self.assertIn("@media (max-width: 560px)", CSS)

    def test_playlist_edits_use_latest_local_data_and_error_reporting(self):
        self.assertIn("async function savePlaylistChange(transform, message, focusId = null)", JS)
        self.assertIn("const { playlists } = await api('/api/playlists');", JS)
        self.assertIn("await api('/api/playlists', { playlists: updated });", JS)
        self.assertIn("Playlist not saved: ", JS)
        self.assertIn("playlistSaveBusy = true", JS)
        self.assertIn("finally { playlistSaveBusy = false; }", JS)
        self.assertIn("focusTarget.focus()", JS)

    def test_non_drag_reordering_and_remove_leave_playback_alone(self):
        self.assertIn("text: 'Move up'", JS)
        self.assertIn("text: 'Move down'", JS)
        self.assertIn("p.tracks.splice(index, 1)", JS)
        self.assertIn("p.tracks[index - 1]", JS)
        self.assertIn("p.tracks[index + 1]", JS)
        self.assertIn("music and licences unchanged", JS)
        self.assertIn("playlist-entries", JS)
        self.assertIn("playlist-edit-actions", CSS)

    def test_rename_and_delete_are_distinct_and_delete_requires_confirmation(self):
        self.assertIn("prompt('Rename playlist'", JS)
        self.assertIn("Delete playlist", JS)
        self.assertIn("if (!confirm('Delete playlist", JS)
        self.assertIn("rows.filter(x => x.id !== playlist.id)", JS)
        self.assertIn("tracks, licences and downloads remain", JS)

    def test_append_queue_does_not_replace_playback_queue(self):
        self.assertIn("async function queueWholePlaylist(playlist)", JS)
        self.assertIn("...state.queue, ...playable", JS)
        self.assertIn("Play now (replace queue)", JS)
        self.assertIn("Start the selected track first", JS)
        self.assertIn("await api('/api/play', { file_id: playable[0] });", JS)
        self.assertIn("await api('/api/queue', { items: playable.slice(1) });", JS)
        self.assertIn("if (!confirm('Play", JS)
        self.assertIn("$('btn-queue').addEventListener('click', () => show('queue')", JS)
        self.assertIn("p.seq < lastSeq", JS)
        self.assertIn("pendingSeek", JS)

    def test_ui_reuses_immutable_track_references_and_safe_dom_text(self):
        self.assertIn("libraryById.get(id)", JS)
        self.assertIn("el('strong', { text: ", JS)
        self.assertNotIn("innerHTML", JS)
        self.assertIn("URL.createObjectURL(image)", JS)
        self.assertIn("showPlayerArtwork(item)", JS)
        self.assertIn('"Inter"', CSS)
        self.assertIn("#ph-play-fill", HTML)

    def test_local_playlist_rename_reorder_and_remove_survive_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            lib = Library(Path(directory) / "library")
            a, b, c = ("a" * 64, "b" * 64, "c" * 64)
            first, second = "1" * 16, "2" * 16
            lib.save_playlists([
                {"id": first, "name": "My mix", "tracks": [a, b, c]},
                {"id": second, "name": "Other playlist", "tracks": [b]},
            ])
            rows = lib.playlists()
            rows[0]["name"] = "Renamed mix"
            rows[0]["tracks"] = [c, a]  # reorder and remove B only from mix
            lib.save_playlists(rows)
            again = Library(Path(directory) / "library")
            self.assertEqual(again.playlists(), [
                {"id": first, "name": "Renamed mix", "tracks": [c, a]},
                {"id": second, "name": "Other playlist", "tracks": [b]},
            ])
            # Deleting a playlist cannot remove another playlist's references.
            again.save_playlists([again.playlists()[1]])
            self.assertEqual(again.playlists()[0]["tracks"], [b])

    def test_invalid_playlist_save_preserves_prior_file(self):
        with tempfile.TemporaryDirectory() as directory:
            lib = Library(Path(directory) / "library")
            good = {"id": "3" * 16, "name": "Keep", "tracks": ["a" * 64]}
            lib.save_playlists([good])
            with self.assertRaises(LibraryError):
                lib.save_playlists([{"id": "oops", "name": "Broken", "tracks": []}])
            self.assertEqual(lib.playlists(), [good])

    def test_existing_playlist_api_is_local_and_still_validates_references(self):
        self.assertIn('("GET", "/api/playlists")', SERVER)
        self.assertIn('("POST", "/api/playlists")', SERVER)
        source = (ROOT / "holochain_music" / "library.py").read_text(encoding="utf-8")
        self.assertIn("MAX_PLAYLIST_TRACKS = 1000", source)
        self.assertIn("def save_playlists(self, playlists: list[dict])", source)
        self.assertIn("_atomic_json(self.root / \"playlists.json\", clean)", source)


if __name__ == "__main__":
    unittest.main()
