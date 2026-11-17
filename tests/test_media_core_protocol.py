"""Always-on adapter contract tests; no Rust executable or production opt-in needed."""
from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from holochain_storage import media_core_adapter as core
from holochain_storage.holochain_identity import AuthoredRecord
from holochain_storage.package import create_package, public_key_bytes
from music_catalogue.content_grants import issue_content_grant
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)


class AdapterProtocolTests(unittest.TestCase):
    def run_fake(self, rc: int, output: bytes):
        completed = subprocess.CompletedProcess([], rc, stdout=output, stderr=b"private stderr")
        with mock.patch.object(core, "binary", return_value=Path("/unused/core")), \
             mock.patch.object(core.subprocess, "run", return_value=completed):
            return core._run(["verify-manifest"])

    def test_exit_statuses_are_not_interchangeable(self):
        self.assertEqual(self.run_fake(0, b'{"ok":true}')["ok"], True)
        with self.assertRaises(core.MediaCoreRejected) as cm:
            self.run_fake(2, b'{"ok":false,"boundary":"s1-manifest","error":"InvalidSignature"}')
        self.assertEqual(cm.exception.error_class, "invalid-content")
        with self.assertRaises(core.MediaCoreRejected) as cm:
            self.run_fake(2, b'{"ok":false,"boundary":"entitlement","category":"denied"}')
        self.assertEqual(cm.exception.error_class, "access-denied")
        with self.assertRaises(core.MediaCoreUnsupportedSchema) as cm:
            self.run_fake(2, b'{"ok":false,"boundary":"entitlement","category":"unsupported"}')
        self.assertEqual(cm.exception.error_class, "unsupported-schema")
        # The CLI currently combines invalid usage and its own I/O failures
        # into exit 1. Never pretend either is an authenticated rejection.
        with self.assertRaises(core.MediaCoreUnavailable):
            self.run_fake(1, b'{"ok":false,"boundary":"usage-or-io","error":"missing file"}')

    def test_invalid_and_oversized_cli_output_is_unavailable(self):
        for rc, data in ((0, b"not JSON"), (0, b"[]"),
                         (0, b'{"ok":false}'), (2, b'{"ok":true}'),
                         (-9, b'{"ok":true}'), (3, b'{"ok":false}'),
                         (0, b"x" * (core.MAX_OUTPUT_BYTES + 1))):
            with self.subTest(rc=rc, size=len(data)):
                with self.assertRaises(core.MediaCoreUnavailable):
                    self.run_fake(rc, data)

    def test_timeout_and_launch_failure_are_unavailable(self):
        with mock.patch.object(core, "binary", return_value=Path("/unused/core")):
            for exc in (subprocess.TimeoutExpired(["core"], 1), OSError("exec failed")):
                with mock.patch.object(core.subprocess, "run", side_effect=exc):
                    with self.assertRaises(core.MediaCoreUnavailable):
                        core._run(["audit"], timeout=1)

    def test_local_input_staging_io_is_distinct(self):
        with mock.patch.object(core.os, "open", side_effect=PermissionError("read-only")):
            with self.assertRaises(core.MediaCoreLocalIO) as cm:
                core._write(Path("/unused"), "public.json", {"x": 1})
        self.assertEqual(cm.exception.error_class, "local-io")

    def test_staged_public_inputs_are_exclusive_and_private(self):
        with core._staging() as directory:
            staged = Path(core._write(directory, "public.json", {"schema": "public"}))
            self.assertEqual(json.loads(staged.read_bytes()), {"schema": "public"})
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o600)
            with self.assertRaises(core.MediaCoreLocalIO) as cm:
                core._write(directory, "public.json", {"schema": "different"})
            self.assertEqual(cm.exception.error_class, "local-io")
            self.assertEqual(json.loads(staged.read_bytes()), {"schema": "public"})

    def test_missing_or_relative_binary_is_not_accepted(self):
        with mock.patch.dict(os.environ, {core.ENV_BINARY: "./not-a-system-binary"}):
            with self.assertRaises(core.MediaCoreUnavailable):
                core.binary()
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.dict(os.environ, {core.ENV_BINARY: str(Path(temporary) / "missing")}):
                with self.assertRaises(core.MediaCoreUnavailable):
                    core.binary()

    def test_temporary_directory_failure_is_local_io(self):
        with mock.patch.object(core.tempfile, "TemporaryDirectory",
                               side_effect=PermissionError("temp directory unavailable")):
            with self.assertRaises(core.MediaCoreLocalIO) as cm:
                core.verify_manifest({"body": {}}, bytes(32))
        self.assertEqual(cm.exception.error_class, "local-io")

    def test_only_public_material_crosses_cli_invocation(self):
        """Inspect both arguments and staged files for every adapter operation."""
        signing_private = Ed25519PrivateKey.generate()
        recipient_private = X25519PrivateKey.generate()
        recipient_public = recipient_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        signing_secret = signing_private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        recipient_secret = recipient_private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        forbidden = []  # raw and common text encodings of *real* test keys
        seen_commands = []

        def inspect(args, timeout=120):
            seen_commands.append(args[0])
            self.assertNotIn("--content-key", args)
            self.assertNotIn("--signing-key-hex", args)
            self.assertNotIn("--recipient-private-hex", args)
            arguments = " ".join(args).encode()
            for private in forbidden:
                self.assertNotIn(private, arguments)
            for index, arg in enumerate(args[:-1]):
                if arg in ("--manifest", "--receipt", "--bridge-json", "--grant"):
                    data = Path(args[index + 1]).read_bytes()
                    for private in forbidden:
                        self.assertNotIn(private, data)
            return {"ok": True}

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "plaintext.bin"
            source.write_bytes(b"Audio bytes never sent to the verification CLI" * 4)
            origin = tmp_path / "origin"
            manifest, content_key = create_package(source, origin, signing_private, chunk_size=64)
            for raw in (signing_secret, recipient_secret, content_key):
                forbidden.extend((raw, raw.hex().encode("ascii"), base64.b64encode(raw)))
            grant = issue_content_grant(
                owner_signer=signing_private, owner_agent="owner", listener_agent="listener",
                recipient_public=recipient_public, signed_manifest=manifest, content_key=content_key)
            receipt = {"body": {"schema": "test-public-receipt"}, "signature": "test"}
            record = AuthoredRecord("owner", "action", {"schema": "public-only"})
            with mock.patch.object(core, "_run", side_effect=inspect):
                core.verify_manifest(manifest, public_key_bytes(signing_private))
                core.verify_receipt(receipt, manifest, bytes(32), public_key_bytes(signing_private))
                core.verify_replica_claim(receipt, manifest, "owner", "node", record, record, record, record)
                core.check_access(grant, manifest, "owner", record, record, "listener",
                                  recipient_public, "stream", 1760000000)
                core.import_into_cas(manifest, public_key_bytes(signing_private), origin, tmp_path / "cas")
                core.audit_cas(manifest, public_key_bytes(signing_private), tmp_path / "cas")
        self.assertEqual(seen_commands, ["verify-manifest", "verify-receipt", "verify-bindings",
                                         "check-access", "import", "audit"])

    def test_accidental_secret_fields_fail_before_spawning_cli(self):
        # Deliberately malformed public input may be compared by the Rust
        # verifier, but never if it carries a named private field.
        for field in ("content_key", "content-key-b64", "recipient_private_key",
                      "recipientPrivateKey", "PRIVATE-KEY-PEM",
                      "plaintextContentKey", "private_signing_key", "owner_signer"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                secret_manifest = {"body": {"schema": "public", field: "SENSITIVE"}}
                with mock.patch.object(core, "_run", side_effect=AssertionError("spawned")):
                    with self.assertRaises(core.MediaCoreUnavailable):
                        core.verify_manifest(secret_manifest, bytes(32))

    def test_non_conductor_records_are_not_accepted(self):
        with self.assertRaises(core.MediaCoreUnavailable):
            core._record({"author": "forged", "body": {}})

    def test_secret_fields_in_conductor_records_and_grants_never_spawn(self):
        safe = AuthoredRecord("owner", "action", {"schema": "public"})
        tainted = AuthoredRecord("owner", "action",
                                {"metadata": [{"recipient-private-key": "SENSITIVE"}]})
        with mock.patch.object(core, "_run", side_effect=AssertionError("spawned")):
            for call in (
                lambda: core.verify_replica_claim({}, {}, "owner", "host",
                                                  safe, tainted, safe, safe),
                lambda: core.check_access({}, {}, "owner", safe, tainted,
                                          "listener", bytes(32), "stream"),
                lambda: core.check_access({"body": {"content_key_b64": "SENSITIVE"}},
                                          {}, "owner", safe, safe,
                                          "listener", bytes(32), "stream"),
            ):
                with self.subTest(call=call), self.assertRaises(core.MediaCoreUnavailable):
                    call()

    @unittest.skipUnless(bool(os.environ.get(core.ENV_BINARY)),
                         "native error-contract comparison needs the CLI")
    def test_native_cli_exit_one_conflates_usage_and_local_io(self):
        # This is evidence of a *remaining* Rust CLI ambiguity, not evidence
        # that a missing file is a bad signature or a denied entitlement.
        def expect_usage_or_io(args):
            completed = subprocess.run(
                [str(core.binary()), *args], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            self.assertEqual(completed.returncode, 1, completed.stdout)
            verdict = json.loads(completed.stdout)
            self.assertIs(verdict["ok"], False)
            self.assertEqual(verdict["boundary"], "usage-or-io")
        expect_usage_or_io(["unsupported-command"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expect_usage_or_io(["verify-manifest", "--manifest", str(root / "missing.json"),
                                "--trusted-artist-hex", "00" * 32])
            signer = Ed25519PrivateKey.generate()
            source = root / "source.bin"
            source.write_bytes(b"Music fixture" * 200)
            manifest, _ = create_package(source, root / "store", signer, chunk_size=64)
            manifest_path = root / "m.json"
            manifest_path.write_bytes(core.canonical(manifest))
            expect_usage_or_io(["audit", "--manifest", str(manifest_path),
                                "--trusted-artist-hex", public_key_bytes(signer).hex(),
                                "--cas", str(root / "nonexistent-cas")])


if __name__ == "__main__":
    unittest.main()
