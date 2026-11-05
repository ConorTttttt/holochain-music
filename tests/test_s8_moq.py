"""S8 real IETF MoQT/QUIC -> AES-GCM ciphertext integrity smoke tests.

The pure-Python tests always run. Real QUIC tests run only when both native
binaries are provided; CI and Ubuntu instructions enable them explicitly.
No fake MoQ transport or mock storage server is used in integration tests.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.request import urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from holochain_storage.network_client import StorageNodeClient
from holochain_storage.package import (
    StorageError, canonical, create_package, decrypt_package, manifest_digest,
    object_path, public_key_bytes, sha256, verify_package, verify_receipt,
)


def reserve_tcp_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class S8ManifestContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="holochain-music-s8-contract-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.artist = Ed25519PrivateKey.generate()
        self.source = self.root / "opaque.flac"
        self.source.write_bytes((b"S8 synthetic ciphertext test source" * 256) + os.urandom(400))
        self.manifest, self.secret = create_package(self.source, self.root / "source", self.artist, chunk_size=1024)

    def test_manifest_and_chunk_hashes_are_independently_verifiable(self):
        self.assertEqual(verify_package(self.manifest, self.root / "source", public_key_bytes(self.artist))["file_id"],
                         self.manifest["body"]["file_id"])
        self.assertEqual(len(self.secret), 32)
        self.assertNotIn(base64.b64encode(self.secret), canonical(self.manifest))

    def test_bad_ciphertext_is_rejected_before_decryption(self):
        chunk = self.manifest["body"]["chunks"][0]
        path = object_path(self.root / "source", chunk["sha256"])
        data = bytearray(path.read_bytes())
        data[0] ^= 1
        path.write_bytes(data)
        with self.assertRaises(StorageError):
            verify_package(self.manifest, self.root / "source", public_key_bytes(self.artist))

    def test_recovery_requires_correct_content_key(self):
        with self.assertRaises(StorageError):
            decrypt_package(self.manifest, self.root / "source", self.root / "wrong.flac", os.urandom(32), public_key_bytes(self.artist))
        restored = decrypt_package(self.manifest, self.root / "source", self.root / "good.flac", self.secret, public_key_bytes(self.artist))
        self.assertEqual(restored.read_bytes(), self.source.read_bytes())


@unittest.skipUnless(os.environ.get("HOLOCHAIN_MOQ_BIN") and os.environ.get("HOLOCHAIN_STORAGE_NODE_BIN"),
                     "set HOLOCHAIN_MOQ_BIN and HOLOCHAIN_STORAGE_NODE_BIN for actual QUIC/S4 tests")
class RealS8MoqTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="holochain-music-s8-network-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.publisher_bin = Path(os.environ["HOLOCHAIN_MOQ_BIN"]).resolve(strict=True)
        self.storage_bin = Path(os.environ["HOLOCHAIN_STORAGE_NODE_BIN"]).resolve(strict=True)
        self.artist = Ed25519PrivateKey.generate()
        self.pub = public_key_bytes(self.artist)
        self.sample = (b"S8 test content, NOT a valid FLAC stream. " * 1024) + os.urandom(1024)
        source = self.root / "sample.flac"
        source.write_bytes(self.sample)
        self.manifest, self.secret = create_package(source, self.root / "source", self.artist, chunk_size=2048)
        self.manifest_file = self.root / "manifest.json"
        self.manifest_file.write_bytes(canonical(self.manifest))
        self.digest = manifest_digest(self.manifest)
        self.node_root = self.root / "node"
        self.url = f"http://127.0.0.1:{reserve_tcp_port()}"
        self.node = subprocess.Popen([
            str(self.storage_bin), "--root", str(self.node_root),
            "--listen", self.url.removeprefix("http://"),
            "--artist-key", base64.b64encode(self.pub).decode("ascii"),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(self.stop_process, self.node)
        for _ in range(100):
            if self.node.poll() is not None:
                self.fail("real S4 storage node exited early")
            try:
                with urlopen(self.url + "/health", timeout=0.2) as r:
                    if r.read() == b"ok":
                        break
            except OSError:
                time.sleep(0.1)
        else:
            self.fail("real S4 storage node did not start")
        # The real S4 node must have accepted and committed the package before
        # the MoQ sidecar is allowed to read the node's ciphertext CAS.
        uploader = StorageNodeClient(self.url, self.artist)
        uploader.upload(self.manifest, self.root / "source")
        node_private = Ed25519PrivateKey.from_private_bytes((self.node_root / "node.ed25519").read_bytes())
        node_public = public_key_bytes(node_private)
        receipt = uploader.commit(self.manifest, node_public)
        verify_receipt(receipt, self.manifest, node_public, self.pub)

    @staticmethod
    def stop_process(proc):
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        if proc.stderr:
            proc.stderr.close()

    def launch_publisher(self):
        ready_file = self.root / f"ready-{time.monotonic_ns()}.json"
        proc = subprocess.Popen([
            str(self.publisher_bin), "publish",
            "--manifest", str(self.manifest_file),
            "--store", str(self.node_root),
            "--trusted-artist-hex", self.pub.hex(),
            "--expected-manifest-sha256", self.digest,
            "--cert-dir", str(self.root / f"cert-{time.monotonic_ns()}"),
            "--ready-file", str(ready_file),
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop_process, proc)
        for _ in range(150):
            if ready_file.is_file():
                return proc, json.loads(ready_file.read_text())
            if proc.poll() is not None:
                err = proc.stderr.read() if proc.stderr else ""
                self.fail(f"MoQ publisher exited before QUIC listening: {err[:4000]}")
            time.sleep(0.1)
        self.fail("MoQ publisher did not write readiness file")

    def receive(self, info, fingerprint=None, digest=None):
        return subprocess.run([
            str(self.publisher_bin), "receive",
            "--manifest", str(self.manifest_file),
            "--store", str(self.root / "listener"),
            "--trusted-artist-hex", self.pub.hex(),
            "--expected-manifest-sha256", digest or self.digest,
            "--url", info["url"],
            "--cert-fingerprint-hex", fingerprint or info["cert_fingerprint_hex"],
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=65)

    def test_real_moq_quic_ciphertext_round_trip(self):
        publisher, info = self.launch_publisher()
        self.assertEqual(info["file_id"], self.manifest["body"]["file_id"])
        self.assertEqual(info["manifest_sha256"], self.digest)
        received = self.receive(info)
        self.assertEqual(received.returncode, 0, received.stderr)
        report = json.loads(received.stdout)
        self.assertTrue(report["verified"])
        self.assertEqual(report["received_chunks"], len(self.manifest["body"]["chunks"]))
        self.assertEqual(report["manifest_sha256"], self.digest)
        self.assertEqual(publisher.wait(timeout=15), 0,
                         publisher.stderr.read() if publisher.stderr else "publisher exited with error")
        verify_package(self.manifest, self.root / "listener", self.pub)
        result = decrypt_package(self.manifest, self.root / "listener", self.root / "recovered.flac", self.secret, self.pub)
        self.assertEqual(sha256(result.read_bytes()), sha256(self.sample))

    def test_tls_fingerprint_mismatch_fails_closed(self):
        _publisher, info = self.launch_publisher()
        self.assertNotEqual(info["cert_fingerprint_hex"], "ff" * 32)
        result = self.receive(info, fingerprint="ff" * 32)
        self.assertNotEqual(result.returncode, 0, "untrusted QUIC peer accepted")
        self.assertFalse((self.root / "listener" / "objects").exists())

    def test_wrong_signed_manifest_pin_fails_before_connect(self):
        _publisher, info = self.launch_publisher()
        result = self.receive(info, digest="aa" * 32)
        self.assertNotEqual(result.returncode, 0, "incorrect Holochain digest accepted")
        self.assertFalse((self.root / "listener" / "objects").exists())

    def test_tampered_s4_replica_refused_by_moq_publisher(self):
        path = object_path(self.node_root, self.manifest["body"]["chunks"][0]["sha256"])
        chunk = bytearray(path.read_bytes())
        chunk[0] ^= 1
        path.write_bytes(chunk)
        ready = self.root / "should-not-exist.json"
        proc = subprocess.run([
            str(self.publisher_bin), "publish", "--manifest", str(self.manifest_file),
            "--store", str(self.node_root), "--trusted-artist-hex", self.pub.hex(),
            "--expected-manifest-sha256", self.digest,
            "--cert-dir", str(self.root / "cert-corrupt"), "--ready-file", str(ready),
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
        self.assertNotEqual(proc.returncode, 0, "corrupt ciphertext was published")
        self.assertFalse(ready.exists(), "publisher announced a corrupted replica")


if __name__ == "__main__":
    unittest.main()
