"""Cross-language S4 integration: real Rust TCP server + S1 Python cryptography.

Run with HOLOCHAIN_STORAGE_NODE_BIN=target/debug/holochain-storage-node
python -m unittest discover -s tests -p test_network_service.py -v
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage.network_client import RemoteStorageError, StorageNodeClient
from holochain_storage.package import (
    StorageError, create_package, decrypt_package, manifest_digest, object_path,
    public_key_bytes, verify_package, verify_receipt,
)


class NetworkedStorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin = os.environ.get("HOLOCHAIN_STORAGE_NODE_BIN")
        if not cls.bin:
            raise unittest.SkipTest("set HOLOCHAIN_STORAGE_NODE_BIN to the compiled Rust binary")
        cls.tmp = tempfile.TemporaryDirectory(prefix="holochain-storage-ci-")
        cls.root = Path(cls.tmp.name)
        cls.artist = Ed25519PrivateKey.generate()
        cls.artist_pub = public_key_bytes(cls.artist)
        cls._start_node()

    @classmethod
    def _start_node(cls):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        cls.url = f"http://127.0.0.1:{cls.port}"
        cmd = [cls.bin, "--root", str(cls.root / "node"), "--listen", f"127.0.0.1:{cls.port}",
               "--artist-key", base64.b64encode(cls.artist_pub).decode()]
        cls.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for _ in range(80):
            if cls.proc.poll() is not None:
                raise AssertionError("server exited before health: " + cls.proc.stderr.read().decode(errors="replace"))
            try:
                with urlopen(cls.url + "/health", timeout=0.2) as resp:
                    if resp.read() == b"ok":
                        break
            except (OSError, URLError):
                time.sleep(0.1)
        else:
            raise AssertionError("server never became healthy")
        cls.node_private = Ed25519PrivateKey.from_private_bytes((cls.root / "node" / "node.ed25519").read_bytes())
        cls.node_pub = public_key_bytes(cls.node_private)
        cls.client = StorageNodeClient(cls.url, cls.artist)

    @classmethod
    def _stop_node(cls):
        if cls.proc.poll() is None:
            cls.proc.terminate()
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait(timeout=5)
        cls.proc.stderr.close()

    @classmethod
    def tearDownClass(cls):
        cls._stop_node()
        cls.tmp.cleanup()

    def package(self, payload: bytes, suffix: str):
        owner = self.root / "packages" / suffix
        owner.mkdir(parents=True, exist_ok=True)
        source = owner / "file.bin"
        source.write_bytes(payload)
        signed, key = create_package(source, owner / "objects", self.artist, chunk_size=1024)
        return signed, key, owner / "objects"

    def test_upload_commit_download_decrypt_multichunk(self):
        original = bytes(range(256)) * 24
        m, key, source_store = self.package(original, "normal")
        self.client.upload(m, source_store)
        receipt = self.client.commit(m, self.node_pub)
        self.assertEqual(receipt["body"]["manifest_sha256"], manifest_digest(m))
        downloaded_store = self.root / "downloads" / "normal"
        self.client.fetch(m, downloaded_store, self.node_pub)
        result = decrypt_package(m, downloaded_store, self.root / "normal.dat", key, self.artist_pub)
        self.assertEqual(result.read_bytes(), original)

    def test_empty_file_package_roundtrip(self):
        m, key, source_store = self.package(b"", "empty")
        self.client.upload(m, source_store)
        receipt = self.client.commit(m, self.node_pub)
        verify_receipt(receipt, m, self.node_pub, self.artist_pub)
        dest = self.root / "downloads" / "empty"
        self.client.fetch(m, dest, self.node_pub)
        result = decrypt_package(m, dest, self.root / "empty.out", key, self.artist_pub)
        self.assertEqual(result.read_bytes(), b"")

    def test_node_does_not_serve_uncommitted_files(self):
        m, _, _ = self.package(b"sensitive but encrypted", "staging")
        self.client.init(m)
        with self.assertRaisesRegex(RemoteStorageError, "404"):
            self.client._request("GET", f"/v1/packages/{m['body']['file_id']}/manifest")
        with self.assertRaisesRegex(RemoteStorageError, "404"):
            self.client._request("GET", f"/v1/packages/{m['body']['file_id']}/chunks/0")
        with self.assertRaisesRegex(RemoteStorageError, "404|409"):
            self.client.commit(m, self.node_pub)  # no chunks uploaded

    def test_cannot_upload_wrong_ciphertext(self):
        m, _, source_store = self.package(b"hello", "tampered")
        self.client.init(m)
        id = m["body"]["file_id"]
        with self.assertRaisesRegex(RemoteStorageError, "400"):
            self.client._request("PUT", f"/v1/packages/{id}/chunks/0", b"incorrect", signed=True)
        self.client.upload(m, source_store)
        self.client.commit(m, self.node_pub)

    def test_two_independent_nodes_survive_artist_source_loss(self):
        """Two distinct Rust node roots, keys and TCP listeners hold full replicas."""
        m, secret, source_store = self.package(bytes(range(256)) * 16, "dual-host")
        self.client.upload(m, source_store)
        self.client.commit(m, self.node_pub)

        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            alt_port = sock.getsockname()[1]
        second_root = self.root / "second-independent-node"
        alt_url = f"http://127.0.0.1:{alt_port}"
        cmd = [self.bin, "--root", str(second_root), "--listen", f"127.0.0.1:{alt_port}",
               "--artist-key", base64.b64encode(self.artist_pub).decode()]
        second = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(80):
                if second.poll() is not None:
                    raise AssertionError("second node exited before health")
                try:
                    with urlopen(alt_url + "/health", timeout=0.2) as response:
                        if response.read() == b"ok":
                            break
                except (OSError, URLError):
                    time.sleep(0.1)
            else:
                raise AssertionError("second node never became healthy")
            second_private = Ed25519PrivateKey.from_private_bytes(
                (second_root / "node.ed25519").read_bytes()
            )
            second_public = public_key_bytes(second_private)
            self.assertNotEqual(second_public, self.node_pub)
            another = StorageNodeClient(alt_url, self.artist)
            another.upload(m, source_store)
            receipt_b = another.commit(m, second_public)
            verify_receipt(receipt_b, m, second_public, self.artist_pub)
            for chunk in m["body"]["chunks"]:
                object_path(source_store, chunk["sha256"]).unlink()
            recovered_store = self.root / "downloads" / "dual-host"
            another.fetch(m, recovered_store, second_public)
            export = decrypt_package(
                m, recovered_store, self.root / "dual-host.out", secret, self.artist_pub
            )
            self.assertEqual(export.read_bytes(), bytes(range(256)) * 16)
        finally:
            second.terminate()
            try:
                second.wait(timeout=5)
            except subprocess.TimeoutExpired:
                second.kill()
                second.wait(timeout=5)
            second.stderr.close()

    def test_wrong_artist_cannot_start_or_upload(self):
        other = StorageNodeClient(self.url, Ed25519PrivateKey.generate())
        m, _, store = self.package(b"artist", "foreign")
        with self.assertRaisesRegex(RemoteStorageError, "403"):
            other.init(m)
        self.client.init(m)
        with self.assertRaisesRegex(RemoteStorageError, "403"):
            other._request("PUT", f"/v1/packages/{m['body']['file_id']}/chunks/0", b"fake", signed=True)

    def test_authenticated_mutation_cannot_be_replayed(self):
        m, _, _ = self.package(b"replay", "replay")
        path = "/v1/packages/init"
        body = json.dumps({"manifest": m}, sort_keys=True, separators=(",", ":")).encode()
        stamp = str(int(time.time()))
        nonce = "0123456789abcdef0123456789abcdef"
        digest = hashlib.sha256(body).hexdigest()
        payload = f"holochain-storage/http-auth/v1\nPOST\n{path}\n{stamp}\n{nonce}\n{digest}".encode()
        headers = {
            "X-HS-Artist-Key": base64.b64encode(self.artist_pub).decode(),
            "X-HS-Timestamp": stamp,
            "X-HS-Nonce": nonce,
            "X-HS-Body-SHA256": digest,
            "X-HS-Signature": base64.b64encode(self.artist.sign(payload)).decode(),
        }
        def send():
            req = Request(self.url + path, data=body, method="POST", headers=headers)
            return urlopen(req, timeout=5)
        with send() as resp:
            self.assertEqual(resp.status, 201)
        with self.assertRaises(HTTPError) as caught:
            send()
        self.assertEqual(caught.exception.code, 403)

    def test_expired_auth_timestamp_is_rejected(self):
        m, _, _ = self.package(b"expired", "expired")
        path = "/v1/packages/init"
        body = json.dumps({"manifest": m}, sort_keys=True, separators=(",", ":")).encode()
        stamp = str(int(time.time()) - 1000)
        nonce = "fedcba9876543210fedcba9876543210"
        digest = hashlib.sha256(body).hexdigest()
        payload = f"holochain-storage/http-auth/v1\nPOST\n{path}\n{stamp}\n{nonce}\n{digest}".encode()
        headers = {
            "X-HS-Artist-Key": base64.b64encode(self.artist_pub).decode(),
            "X-HS-Timestamp": stamp,
            "X-HS-Nonce": nonce,
            "X-HS-Body-SHA256": digest,
            "X-HS-Signature": base64.b64encode(self.artist.sign(payload)).decode(),
        }
        with self.assertRaises(HTTPError) as caught:
            urlopen(Request(self.url + path, data=body, method="POST", headers=headers), timeout=5)
        self.assertEqual(caught.exception.code, 403)

    def test_client_refuses_wrong_pinned_node_key(self):
        m, _, source_store = self.package(b"receipt check", "receipt")
        self.client.upload(m, source_store)
        with self.assertRaises(StorageError):
            self.client.commit(m, public_key_bytes(Ed25519PrivateKey.generate()))

    def test_same_package_upload_is_idempotent_but_commit_freezes_it(self):
        m, _, source_store = self.package(b"identical bytes", "repeat")
        self.client.upload(m, source_store)
        self.client.upload(m, source_store)
        receipt_a = self.client.commit(m, self.node_pub)
        receipt_b = self.client.commit(m, self.node_pub)
        self.assertEqual(receipt_a, receipt_b)
        chunk = m["body"]["chunks"][0]
        with self.assertRaisesRegex(RemoteStorageError, "409"):
            self.client._request("PUT", f"/v1/packages/{m['body']['file_id']}/chunks/0", object_path(source_store, chunk["sha256"]).read_bytes(), signed=True)

    def test_node_signer_persists_restart_and_existing_file_is_available(self):
        m, key, source_store = self.package(b"durability across process restart", "restart")
        self.client.upload(m, source_store)
        self.client.commit(m, self.node_pub)
        pub_before = self.node_pub
        self._stop_node()
        self._start_node()
        self.assertEqual(self.node_pub, pub_before)
        target = self.root / "downloads" / "restart"
        self.client.fetch(m, target, self.node_pub)
        out = decrypt_package(m, target, self.root / "restart.out", key, self.artist_pub)
        self.assertEqual(out.read_bytes(), b"durability across process restart")


if __name__ == "__main__":
    unittest.main()
