"""Opt-in adapter to Holochain Media Core's Rust verifier and VerifiedCas.

DISABLED unless ``HOLOCHAIN_MEDIA_CORE_BIN`` names the ``holochain-media-core``
executable built from ConorTttttt/holochain-media-core (CORE-004). No Music
production path calls this module: the existing Python S1/S2 code remains the
read/write path. This module exists so Music can compare both implementations
on the same packages before any switch is considered.

Boundary (deliberately small, same model as ``holochain-music-moq`` and
``music_conductor_bridge``): a supervised local subprocess that receives only
PUBLIC material (signed manifest/receipt JSON, public keys, conductor-bridge
records, ciphertext directories) and prints one JSON object. Content keys,
X25519 *private* keys and private signing keys are never passed to it, and it
never decrypts or unwraps. ``check_access`` (CORE-005) additionally passes an
owner-signed, recipient-wrapped grant/licence and the listener's X25519
*public* key, so Rust can verify the same entitlement Python verifies; the
key inside the grant stays wrapped. Licences, playback and export are
unchanged: no production path calls this module.

Media Core's VerifiedCas uses the same on-disk layout as Music
(``objects/sha256/<2 hex>/<sha256>``), so Music's ``verify_package``,
``decrypt_package`` and ``play_granted_wav`` read a Media Core store as-is.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from . import portable
from .holochain_identity import AuthoredRecord
from .package import canonical

ENV_BINARY = "HOLOCHAIN_MEDIA_CORE_BIN"
MAX_OUTPUT_BYTES = 64 * 1024


class MediaCoreUnavailable(RuntimeError):
    """Adapter not configured or the binary could not run (not a rejection)."""


class MediaCoreRejected(ValueError):
    """Media Core rejected the input at a named verification boundary."""

    def __init__(self, result: dict):
        super().__init__(f"{result.get('boundary')}: {result.get('error')}")
        self.boundary = result.get("boundary")
        self.result = result


def binary() -> Path | None:
    """The configured executable, or None when the adapter is disabled."""
    value = os.environ.get(ENV_BINARY)
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute() or not path.is_file():
        raise MediaCoreUnavailable(f"{ENV_BINARY} must be an existing absolute path")
    return path


def enabled() -> bool:
    return binary() is not None


def _run(args: list[str], timeout: float = 120) -> dict:
    exe = binary()
    if exe is None:
        raise MediaCoreUnavailable(f"{ENV_BINARY} is not set")
    try:
        done = subprocess.run([str(exe), *args], stdin=subprocess.DEVNULL, capture_output=True,
                              timeout=timeout, check=False, **portable.popen_kwargs())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MediaCoreUnavailable("Media Core adapter did not run") from exc
    if len(done.stdout) > MAX_OUTPUT_BYTES:
        raise MediaCoreUnavailable("oversized Media Core output")
    try:
        result = json.loads(done.stdout)
    except ValueError as exc:
        raise MediaCoreUnavailable("non-JSON Media Core output") from exc
    if not isinstance(result, dict):
        raise MediaCoreUnavailable("invalid Media Core output")
    if done.returncode == 0 and result.get("ok") is True:
        return result
    if done.returncode == 2 and result.get("ok") is False:
        raise MediaCoreRejected(result)
    # Exit 1 (usage/I/O) or anything unexpected is NOT a verification result.
    raise MediaCoreUnavailable(f"Media Core failed: {result.get('error')}")


def _write(directory: Path, name: str, value: Any) -> str:
    path = directory / name
    path.write_bytes(canonical(value))
    return str(path)


def verify_manifest(signed_manifest: dict, trusted_artist: bytes,
                    expected_manifest_sha256: str | None = None) -> dict:
    with tempfile.TemporaryDirectory(prefix="hm-core-") as tmp:
        args = ["verify-manifest", "--manifest", _write(Path(tmp), "m.json", signed_manifest),
                "--trusted-artist-hex", trusted_artist.hex()]
        if expected_manifest_sha256 is not None:
            args += ["--expected-manifest-sha256", expected_manifest_sha256]
        return _run(args)


def verify_receipt(receipt: dict, signed_manifest: dict, trusted_node: bytes,
                   trusted_artist: bytes) -> dict:
    with tempfile.TemporaryDirectory(prefix="hm-core-") as tmp:
        return _run(["verify-receipt",
                     "--manifest", _write(Path(tmp), "m.json", signed_manifest),
                     "--receipt", _write(Path(tmp), "r.json", receipt),
                     "--trusted-artist-hex", trusted_artist.hex(),
                     "--trusted-host-hex", trusted_node.hex()])


def _record(record: AuthoredRecord) -> dict:
    if not isinstance(record, AuthoredRecord):
        raise MediaCoreUnavailable("expected a conductor-authenticated AuthoredRecord")
    return {"author": record.author, "action_hash": record.action_hash, "body": record.body}


def verify_replica_claim(receipt: dict, signed_manifest: dict, owner_agent: str, node_agent: str,
                         owner_key_binding: AuthoredRecord, node_key_binding: AuthoredRecord,
                         owner_commitment: AuthoredRecord, node_claim: AuthoredRecord) -> dict:
    """Rust counterpart of ``holochain_identity.verify_replica_claim``.

    The records must come from the trusted local conductor bridge, exactly as
    for the Python function.
    """
    bridge = {"owner_key_binding": _record(owner_key_binding),
              "owner_commitment": _record(owner_commitment),
              "node_key_binding": _record(node_key_binding),
              "replica_claim": _record(node_claim)}
    with tempfile.TemporaryDirectory(prefix="hm-core-") as tmp:
        return _run(["verify-bindings",
                     "--bridge-json", _write(Path(tmp), "bridge.json", bridge),
                     "--manifest", _write(Path(tmp), "m.json", signed_manifest),
                     "--receipt", _write(Path(tmp), "r.json", receipt),
                     "--owner-agent", owner_agent, "--node-agent", node_agent])


RIGHTS = ("stream", "managed-offline", "export")


def check_access(grant: dict, signed_manifest: dict, owner_agent: str,
                 owner_key_binding: AuthoredRecord, owner_commitment: AuthoredRecord,
                 listener_agent: str, recipient_public: bytes, right: str,
                 now: int | None = None) -> dict:
    """Rust (CORE-005) counterpart of ``unwrap_content_grant``'s policy checks.

    The owner identity and key come only from the conductor-authenticated
    ``AuthoredRecord``s, exactly as for ``verify_replica_claim``; the listener
    agent and X25519 *public* key are this device's own trusted context.
    ``right`` is one of ``RIGHTS``. Acceptance is a policy decision only: it
    does not show that the wrapped key decrypts, so Music's own unwrap (with
    AES-GCM authentication) is still required before any plaintext access.
    Rejections raise ``MediaCoreRejected`` with ``boundary`` ``s2-binding`` or
    ``entitlement`` (plus ``category``/``reason``).
    """
    if right not in RIGHTS:
        raise MediaCoreUnavailable("invalid right")
    if not isinstance(recipient_public, bytes) or len(recipient_public) != 32:
        raise MediaCoreUnavailable("recipient X25519 public key must have 32 bytes")
    bridge = {"owner_key_binding": _record(owner_key_binding),
              "owner_commitment": _record(owner_commitment)}
    with tempfile.TemporaryDirectory(prefix="hm-core-") as tmp:
        args = ["check-access",
                "--bridge-json", _write(Path(tmp), "bridge.json", bridge),
                "--manifest", _write(Path(tmp), "m.json", signed_manifest),
                "--owner-agent", owner_agent,
                "--grant", _write(Path(tmp), "g.json", grant),
                "--listener-agent", listener_agent,
                "--recipient-x25519-hex", recipient_public.hex(),
                "--right", right]
        if now is not None:
            if type(now) is not int or now < 0:
                raise MediaCoreUnavailable("now must be non-negative Unix seconds")
            args += ["--now", str(now)]
        return _run(args)


def import_into_cas(signed_manifest: dict, trusted_artist: bytes, source_store: str | Path,
                    cas_root: str | Path) -> dict:
    """Copy verified ciphertext from a Music store into a Media Core CAS."""
    with tempfile.TemporaryDirectory(prefix="hm-core-") as tmp:
        return _run(["import", "--manifest", _write(Path(tmp), "m.json", signed_manifest),
                     "--trusted-artist-hex", trusted_artist.hex(),
                     "--source-store", str(source_store), "--cas", str(cas_root)])


def audit_cas(signed_manifest: dict, trusted_artist: bytes, cas_root: str | Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="hm-core-") as tmp:
        return _run(["audit", "--manifest", _write(Path(tmp), "m.json", signed_manifest),
                     "--trusted-artist-hex", trusted_artist.hex(), "--cas", str(cas_root)])
