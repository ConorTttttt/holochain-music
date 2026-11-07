"""Offline Library P0: rights separation and explicit offline verification.

Run: python3 -m unittest discover -s tests -p 'test_ui_offline_library.py' -v
UI assertions are static; physical offline audio and independent WAV playback
still require separate tests on the real devices.
"""
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from holochain_music.app import MusicApp, AppError
from holochain_storage.package import StorageError
from music_catalogue.content_grants import LICENCE_SCHEMA, GRANT_SCHEMA

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "holochain_music/ui/app.js").read_text(encoding="utf-8")
CSS = (ROOT / "holochain_music/ui/app.css").read_text(encoding="utf-8")
SERVER = (ROOT / "holochain_music/server.py").read_text(encoding="utf-8")
FILE_ID = "a" * 64
META = {
    "file_id": FILE_ID, "artist_key_hex": "b" * 64,
    "artist_agent": "artist", "listener_agent": "listener",
}
LICENCE = {"body": {"schema": LICENCE_SCHEMA}}
STREAM = {"body": {"schema": GRANT_SCHEMA}}


def app_with(grant=LICENCE, complete=True):
    # No conductor, network, CAS or audio engine is started.
    app = MusicApp.__new__(MusicApp)
    app.library = MagicMock()
    app.library.meta.return_value = dict(META)
    app.library.grant.return_value = grant
    app.library.verify_complete.return_value = complete
    app.library.manifest.return_value = {"body": {}}
    app.keys = SimpleNamespace(listener_x25519=lambda: object())
    return app


class OfflineLibraryTests(TestCase):
    def test_no_licence_cannot_be_claimed_offline_ready(self):
        app = app_with(grant=None)
        result = app.offline_readiness(FILE_ID)
        self.assertEqual(result["state"], "no_licence")
        app.library.verify_complete.assert_not_called()

    def test_unknown_file_rejected_before_reading_grants(self):
        app = app_with()
        app.library.meta.return_value = None
        with self.assertRaises(AppError):
            app.offline_readiness(FILE_ID)
        app.library.grant.assert_not_called()

    def test_stream_grant_not_mistaken_for_offline_rental(self):
        app = app_with(grant=STREAM)
        self.assertEqual(app.offline_readiness(FILE_ID)["state"], "temporary_access")
        app.library.verify_complete.assert_not_called()

    def test_missing_chunks_not_ready_even_with_permanent_grant(self):
        app = app_with(complete=False)
        with patch("holochain_music.app.unwrap_content_grant") as unwrap:
            result = app.offline_readiness(FILE_ID)
            self.assertEqual(result["state"], "incomplete")
            unwrap.assert_not_called()

    def test_offline_ready_requires_verified_chunks_and_unwrapped_grant_key(self):
        app = app_with()
        with patch("holochain_music.app.unwrap_content_grant", return_value=b"x" * 32) as unwrap:
            result = app.offline_readiness(FILE_ID)
        self.assertEqual(result["state"], "ready")
        app.library.verify_complete.assert_called_once_with(FILE_ID)
        unwrap.assert_called_once()
        self.assertNotIn("key", result)
        self.assertNotIn("private", repr(result).lower())

    def test_unwrap_failure_is_safe_and_does_not_leak_private_path(self):
        app = app_with()
        with patch("holochain_music.app.unwrap_content_grant",
                   side_effect=StorageError("SECRET /home/private/keys")):
            result = app.offline_readiness(FILE_ID)
        self.assertEqual(result["state"], "missing_key")
        self.assertNotIn("SECRET", str(result))
        self.assertNotIn("/home/private", str(result))

    def test_disk_error_during_verification_is_actionable_and_safe(self):
        app = app_with()
        app.library.verify_complete.side_effect = OSError("SECRET underlying device path")
        result = app.offline_readiness(FILE_ID)
        self.assertEqual(result["state"], "storage_error")
        self.assertNotIn("SECRET", str(result))

    def test_manual_offline_download_rejects_streaming_grants(self):
        app = app_with(grant=STREAM)
        app._ensure_download = MagicMock()
        with self.assertRaisesRegex(AppError, "permanent personal-use licence"):
            app.download(FILE_ID)
        app._ensure_download.assert_not_called()

    def test_manual_offline_download_can_start_for_permanent_grant(self):
        app = app_with()
        app._ensure_download = MagicMock(return_value=None)
        self.assertEqual(app.download(FILE_ID), {"state": "complete"})
        app._ensure_download.assert_called_once_with(FILE_ID)

    def test_offline_dashboard_shows_separate_categories(self):
        self.assertIn("function renderOfflineDashboard(rows)", JS)
        self.assertIn("Ready to listen", JS)
        self.assertIn("Independent licensed exports", JS)
        self.assertIn("Storage and safety", JS)
        self.assertIn("function downloadStateText(item)", JS)
        self.assertIn("function offlineTrackCard(item)", JS)
        self.assertIn("results.replaceChildren(renderOfflineDashboard(rows))", JS)
        self.assertIn(".offline-track-card", CSS)

    def test_chunk_progress_from_actual_receiver_counts_not_fabricated_bytes(self):
        self.assertIn("transfer.available_chunks", JS)
        self.assertIn("transfer.total_chunks", JS)
        self.assertIn("Math.round(100 * found / total)", JS)
        self.assertIn("el('progress'", JS)
        self.assertIn("Retry download", JS)
        self.assertIn("disabled: !state.online || Boolean(busy)", JS)

    def test_export_acknowledges_written_wav_not_independent_playback(self):
        self.assertIn("'/api/export', { file_id: item.file_id, path }", JS)
        self.assertIn("if (!result.exported)", JS)
        self.assertIn("Independent playback in another player has not been verified", JS)
        self.assertIn("Existing files are never overwritten", JS)
        self.assertIn("Export licensed WAV", JS)
        self.assertNotIn("Export Purchased File", JS)

    def test_explicit_verify_endpoint_cannot_be_called_by_library_poll(self):
        self.assertIn('("POST", "/api/offline/verify")', SERVER)
        self.assertIn("app.offline_readiness(_keys(d, {", SERVER)
        self.assertIn("api('/api/offline/verify', { file_id: fileId })", JS)
        self.assertIn("const offlineChecks = new Map()", JS)
        self.assertIn("if (view === 'library' && libraryFilters.scope === 'offline') render();", JS)
        app_source = (ROOT / "holochain_music" / "app.py").read_text(encoding="utf-8")
        getter = app_source.split("    def library_view(self)", 1)[1].split("    # ---- playback", 1)[0]
        self.assertNotIn("offline_readiness(", getter)
        self.assertIn("verify_complete(file_id)", app_source)

    def test_existing_playback_engine_stays_unmodified(self):
        self.assertIn("p.seq < lastSeq", JS)
        self.assertIn("pendingSeek", JS)
        self.assertIn("showPlayerArtwork(item)", JS)
        self.assertIn("$('btn-queue').addEventListener('click', () => show('queue')", JS)
        self.assertNotIn("new Audio(", JS)
        self.assertIn('"Inter"', CSS)


if __name__ == "__main__":
    import unittest
    unittest.main()
