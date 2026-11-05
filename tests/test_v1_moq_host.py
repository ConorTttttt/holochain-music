"""v1 long-running MoQ host + subscriber-driven fetch over real QUIC.

Real-network tests run only with HOLOCHAIN_MOQ_BIN (the actual Rust binary);
no fake transport is used. Contract tests always run.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import threading
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from holochain_storage.package import (
    StorageError, canonical, create_package, manifest_digest, object_path,
    public_key_bytes, verify_package,
)
from music_catalogue.moq_host import (
    MoqFetchCancelled, MoqFetchError, MoqHost, fetch_ciphertext,
)


class Fixture:
    def __init__(self, root: Path, size: int = 40_000, chunk: int = 2048):
        self.root = root
        self.artist = Ed25519PrivateKey.generate()
        self.artist_pub = public_key_bytes(self.artist)
        source = root / "source.bin"
        source.write_bytes(os.urandom(size))
        self.host_store = root / "host-cas"
        self.manifest, _key = create_package(source, self.host_store, self.artist, chunk_size=chunk)
        source.unlink()
        self.digest = manifest_digest(self.manifest)
        self.manifest_path = root / "manifest.json"
        self.manifest_path.write_bytes(canonical(self.manifest))
        self.chunks = self.manifest["body"]["chunks"]

    def entry(self):
        return {"manifest": self.manifest_path, "trusted_artist_hex": self.artist_pub.hex(),
                "manifest_sha256": self.digest}


class FetchContractTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="hm-v1-moq-contract-")
        self.addCleanup(tmp.cleanup)
        self.fx = Fixture(Path(tmp.name), size=5000, chunk=1024)
        self.kw = dict(moq_binary="/nonexistent", signed_manifest=self.fx.manifest,
                       trusted_artist=self.fx.artist_pub, expected_manifest_sha256=self.fx.digest,
                       store=Path(tmp.name) / "listener", url="https://127.0.0.1:4433",
                       cert_fingerprint_hex="a" * 64)

    def test_rejects_wrong_pins_and_unbounded_requests_before_network(self):
        cases = [
            dict(expected_manifest_sha256="b" * 64),
            dict(trusted_artist=public_key_bytes(Ed25519PrivateKey.generate())),
            dict(url="https://8.8.8.8:4433"),
            dict(url="https://192.168.1.4:4433"),  # LAN requires explicit opt-in
            dict(cert_fingerprint_hex="A" * 64),
            dict(start_index=len(self.fx.chunks)),
            dict(objects=[]),
            dict(objects=[0, 0]),
            dict(objects=[len(self.fx.chunks)]),
            dict(objects=list(range(257))),
        ]
        for override in cases:
            with self.subTest(override=list(override)):
                with self.assertRaises((MoqFetchError, StorageError)):
                    fetch_ciphertext(**{**self.kw, **override})


@unittest.skipUnless(os.environ.get("HOLOCHAIN_MOQ_BIN"), "set HOLOCHAIN_MOQ_BIN for real QUIC tests")
class RealMoqHostTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="hm-v1-moq-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.binary = Path(os.environ["HOLOCHAIN_MOQ_BIN"]).resolve(strict=True)
        self.fx = Fixture(self.root)
        self.host = MoqHost(moq_binary=self.binary, store=self.fx.host_store,
                            cert_dir=self.root / "cert", state_dir=self.root / "host-state")
        self.host.set_files([self.fx.entry()])
        self.host.start()
        self.addCleanup(self.host.stop)

    def fetch(self, store, **kw):
        return fetch_ciphertext(moq_binary=self.binary, signed_manifest=self.fx.manifest,
                                trusted_artist=self.fx.artist_pub,
                                expected_manifest_sha256=self.fx.digest, store=store,
                                url=self.host.url, cert_fingerprint_hex=self.host.fingerprint,
                                stall_timeout=10, **kw)

    def test_full_stream_then_package_verifies(self):
        seen = []
        report = self.fetch(self.root / "bob", on_chunk=seen.append)
        self.assertEqual(report["received_chunks"], len(self.fx.chunks))
        self.assertEqual(seen, list(range(len(self.fx.chunks))))
        verify_package(self.fx.manifest, self.root / "bob", self.fx.artist_pub)

    def test_seek_prioritised_start_then_listener_driven_backfill(self):
        store = self.root / "bob"
        middle = len(self.fx.chunks) // 2
        self.fetch(store, start_index=middle)
        for chunk in self.fx.chunks[:middle]:
            self.assertFalse(object_path(store, chunk["sha256"]).exists())
        # Multiple listener-chosen objects in one session, in the asked order.
        seen = []
        self.fetch(store, objects=list(reversed(range(middle))), on_chunk=seen.append)
        self.assertEqual(seen, list(reversed(range(middle))))
        verify_package(self.fx.manifest, store, self.fx.artist_pub)

    def test_two_concurrent_listeners_are_served(self):
        errors = []

        def run(name):
            try:
                self.fetch(self.root / name)
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)
        threads = [threading.Thread(target=run, args=(n,)) for n in ("a", "b")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        self.assertEqual(errors, [])
        for n in ("a", "b"):
            verify_package(self.fx.manifest, self.root / n, self.fx.artist_pub)

    def test_wrong_certificate_pin_is_refused_and_nothing_stored(self):
        store = self.root / "mallory"
        with self.assertRaises(MoqFetchError):
            fetch_ciphertext(moq_binary=self.binary, signed_manifest=self.fx.manifest,
                             trusted_artist=self.fx.artist_pub,
                             expected_manifest_sha256=self.fx.digest, store=store,
                             url=self.host.url, cert_fingerprint_hex="0" * 64, stall_timeout=5)
        self.assertFalse((store / "objects").exists())

    def test_unserved_file_fails_closed(self):
        (self.root / "other").mkdir()
        other = Fixture(self.root / "other")
        with self.assertRaises(MoqFetchError):
            fetch_ciphertext(moq_binary=self.binary, signed_manifest=other.manifest,
                             trusted_artist=other.artist_pub,
                             expected_manifest_sha256=other.digest, store=self.root / "x",
                             url=self.host.url, cert_fingerprint_hex=self.host.fingerprint,
                             stall_timeout=5)

    def test_corrupted_host_object_is_never_delivered(self):
        bad = self.fx.chunks[3]
        path = object_path(self.fx.host_store, bad["sha256"])
        data = bytearray(path.read_bytes())
        data[0] ^= 0xFF
        path.write_bytes(data)
        store = self.root / "bob"
        with self.assertRaises(MoqFetchError):
            self.fetch(store)
        self.assertFalse(object_path(store, bad["sha256"]).exists())
        for chunk in self.fx.chunks[:3]:
            self.assertTrue(object_path(store, chunk["sha256"]).exists())

    def test_restart_keeps_the_published_certificate_fingerprint(self):
        first = self.host.fingerprint
        self.host.start()
        self.assertEqual(self.host.fingerprint, first)
        self.assertEqual((self.root / "cert" / "host.key").stat().st_mode & 0o777, 0o600)
        self.fetch(self.root / "after-restart")

    def test_host_offline_then_resume_from_first_missing_object(self):
        store = self.root / "bob"
        middle = len(self.fx.chunks) // 2
        self.fetch(store, objects=list(range(middle)))
        url, pin = self.host.url, self.host.fingerprint
        self.host.stop()
        with self.assertRaises(MoqFetchError):
            fetch_ciphertext(moq_binary=self.binary, signed_manifest=self.fx.manifest,
                             trusted_artist=self.fx.artist_pub, expected_manifest_sha256=self.fx.digest,
                             store=store, url=url, cert_fingerprint_hex=pin, start_index=middle,
                             stall_timeout=3)
        self.host.start()
        self.fetch(store, start_index=middle)
        verify_package(self.fx.manifest, store, self.fx.artist_pub)

    def test_cancel_stops_promptly(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(MoqFetchCancelled):
            self.fetch(self.root / "bob", cancel=cancel)


if __name__ == "__main__":
    unittest.main()
