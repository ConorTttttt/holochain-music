"""Policy tests for the ciphertext-only media adapter (no network, no MoQ)."""
from __future__ import annotations

import http.client
import json
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import media_adapter as ma  # noqa: E402

HOST = "https://127.0.0.1:4433"
FP = "f" * 64
FILE = "a" * 64


class FakeTransfers(ma.Transfers):
    def __init__(self):
        super().__init__(moq_binary=Path("/bin/true"), cache=Path("/nonexistent"), allow_lan=False,
                         max_files=2, chunk_wait=1, stall_timeout=1)
        self.calls = []

    def document(self, url, fp, file_id, kind):
        self.calls.append(("document", url, fp, file_id, kind))
        return b'{"body":{},"signer":"x","signature":"y"}'

    def chunk(self, url, fp, file_id, digest, artist, index):
        self.calls.append(("chunk", url, fp, file_id, digest, artist.hex(), index))
        return b"\x00" * 32


class AdapterPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.transfers = FakeTransfers()
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), ma.make_handler(cls.transfers, frozenset({"http://localhost:8080"})))
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def get(self, path, origin=None, method="GET"):
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=5)
        c.request(method, path, headers={"Origin": origin} if origin else {})
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read()

    def test_serves_documents_and_chunks_for_allowed_origin(self):
        s, h, body = self.get(f"/v1/files/{FILE}/manifest?host={HOST}&fp={FP}", origin="http://localhost:8080")
        self.assertEqual(s, 200)
        self.assertEqual(h["Access-Control-Allow-Origin"], "http://localhost:8080")
        self.assertEqual(h["Cache-Control"], "no-store")
        s, h, body = self.get(f"/v1/files/{FILE}/chunks/3?host={HOST}&fp={FP}&manifest_sha256={'b' * 64}&artist_key={'c' * 64}")
        self.assertEqual((s, len(body)), (200, 32))
        self.assertEqual(self.transfers.calls[-1], ("chunk", HOST, FP, FILE, "b" * 64, "c" * 64, 3))

    def test_refuses_foreign_origins_and_non_get(self):
        self.assertEqual(self.get(f"/v1/files/{FILE}/manifest?host={HOST}&fp={FP}", origin="https://evil.example")[0], 403)
        for method in ("POST", "PUT", "DELETE", "OPTIONS"):
            self.assertEqual(self.get(f"/v1/files/{FILE}/manifest?host={HOST}&fp={FP}", method=method)[0], 405, method)

    def test_refuses_public_dns_and_malformed_hosts(self):
        for host in ("https://8.8.8.8:443", "https://example.org:443", "http://127.0.0.1:4433",
                     "https://192.168.1.2:4433", "https://127.0.0.1:4433/x", "https://127.0.0.1:0"):
            s, _, body = self.get(f"/v1/files/{FILE}/manifest?host={host}&fp={FP}")
            self.assertEqual(s, 403, host)
            self.assertIn("not permitted", json.loads(body)["error"])

    def test_strict_paths_and_parameters(self):
        bad = [
            f"/v1/files/{FILE.upper()}/manifest?host={HOST}&fp={FP}",
            f"/v1/files/{FILE}/secret?host={HOST}&fp={FP}",
            f"/v1/files/{FILE}/chunks/01?host={HOST}&fp={FP}&manifest_sha256={'b' * 64}&artist_key={'c' * 64}",
            f"/v1/files/{FILE}/chunks/-1?host={HOST}&fp={FP}&manifest_sha256={'b' * 64}&artist_key={'c' * 64}",
            f"/v1/files/{FILE}/chunks/1?host={HOST}&fp={FP}&manifest_sha256=xyz&artist_key={'c' * 64}",
            f"/v1/files/{FILE}/manifest?host={HOST}&fp=short",
            "/admin",
        ]
        for path in bad:
            self.assertIn(self.get(path)[0], (400, 403, 404), path)
        self.assertEqual(self.get("/v1/x?" + "a" * 2000)[0], 414)

    def test_no_secret_material_in_api_surface(self):
        # The adapter accepts only public values; there is no parameter for a key, grant or plaintext.
        source = Path(ma.__file__).read_text()
        for word in ("content_key", "grant_json", "x25519", "recipient"):
            self.assertNotIn(f'q.get("{word}")', source)


if __name__ == "__main__":
    unittest.main()
