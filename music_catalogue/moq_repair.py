"""S15 opt-in, one-object ciphertext repair over a *separate pinned MoQ/QUIC session*.

The trusted HTTPS-over-QUIC endpoint and TLS fingerprint MUST be taken from
Bob's previously verified local Holochain conductor (S9), NEVER from a remote
ready file or the repair sender itself. The signed S1 artist manifest commits
uniquely to the requested index and hash. No plaintext/key/grant is sent to
MoQ. This prototype requires the host to preselect the index for its second
QUIC session; arbitrary subscriber-driven indices and automatic session retry
are not yet implemented. The original S14 S4 HTTP recovery remains separate.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from holochain_storage.package import (
    StorageError, _assert_manifest, _read_verified_chunk, _verify_signed,
    canonical, manifest_digest, object_path, verify_package,
)
from .granted_audio import PlaybackError
from .moq_conductor import _bound_local_url
from .live_conductor import ConductorBridgeError

SCHEMA_FIELDS = {
    "repair_verified", "repair_index", "cipher_bytes", "manifest_sha256",
    "file_id", "repair_transport",
}
REPAIR_TRANSPORT = "pinned-moq-quic-v1"


def _fingerprint(pin: str) -> None:
    if not isinstance(pin, str) or len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
        raise PlaybackError("invalid Holochain-authenticated MoQ certificate fingerprint")


def repair_missing_ciphertext_over_moq(
    *, signed_manifest: dict, ciphertext_store: str | Path,
    trusted_artist: bytes, expected_manifest_sha256: str,
    moq_binary: str | Path, moq_url: str, moq_cert_fingerprint_hex: str,
    timeout: int = 60,
) -> dict:
    """Fetch exactly one missing signed S1 ciphertext CAS object via pinned MoQ.

    The caller must *already* have verified the Holochain endpoint and host
    identity through S9/S14's independent DNA pins. Transport JSON isn't
    trusted: we independently rehash the written CAS object and verify the
    entire local package after repair. Never repair corrupt existing objects.
    """
    if not isinstance(trusted_artist, bytes) or len(trusted_artist) != 32:
        raise PlaybackError("S15 requires trusted artist signer")
    try:
        body = _verify_signed(signed_manifest, trusted_artist, "manifest")
        _assert_manifest(body)
    except (StorageError, TypeError, ValueError) as exc:
        raise PlaybackError("S15 invalid signed artist manifest") from exc
    digest = manifest_digest(signed_manifest)
    if expected_manifest_sha256 != digest:
        raise PlaybackError("S15 signed manifest does not match Holochain pin")
    if type(timeout) is not int or not 1 <= timeout <= 120:
        raise PlaybackError("invalid S15 MoQ repair timeout")
    try:
        _bound_local_url(moq_url)
    except ConductorBridgeError as exc:
        raise PlaybackError("S15 requires Holochain-verified loopback QUIC endpoint") from exc
    _fingerprint(moq_cert_fingerprint_hex)
    binary = Path(moq_binary).expanduser()
    if not binary.is_absolute() or not binary.is_file():
        raise PlaybackError("S15 requires existing trusted absolute MoQ binary")

    target = Path(ciphertext_store)
    missing = []
    for chunk in body["chunks"]:
        path = object_path(target, chunk["sha256"])
        if path.is_symlink():
            raise PlaybackError("S15 refuses symlinked local CAS object")
        if path.exists():
            _read_verified_chunk(target, chunk)
        else:
            missing.append(chunk)
    if len(missing) > 1:
        raise PlaybackError("S15 prototype permits exactly one selected missing CAS object")
    if not missing:
        verify_package(signed_manifest, target, trusted_artist)
        return {"repair_complete": True, "recovered_objects": 0,
                "reused_objects": len(body["chunks"]), "total_objects": len(body["chunks"]),
                "manifest_sha256": digest, "repair_transport": REPAIR_TRANSPORT}

    chunk = missing[0]
    with tempfile.TemporaryDirectory(prefix="holochain-music-s15-manifest-") as d:
        manifest_file = Path(d) / "signed-manifest.json"
        manifest_file.write_bytes(canonical(signed_manifest))
        argv = [str(binary), "repair-receive",
                "--manifest", str(manifest_file), "--store", str(target),
                "--trusted-artist-hex", trusted_artist.hex(),
                "--expected-manifest-sha256", digest,
                "--url", moq_url,
                "--cert-fingerprint-hex", moq_cert_fingerprint_hex,
                "--index", str(chunk["index"])]
        try:
            completed = subprocess.run(argv, capture_output=True, text=True,
                                       timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PlaybackError("S15 pinned MoQ selective repair failed") from exc
    if completed.returncode != 0 or len(completed.stdout.encode("utf-8")) > 4096:
        raise PlaybackError("S15 MoQ selective repair subprocess rejected the transfer")
    try:
        event = json.loads(completed.stdout)
    except (ValueError, TypeError) as exc:
        raise PlaybackError("S15 MoQ repair returned invalid report") from exc
    if (not isinstance(event, dict) or set(event) != SCHEMA_FIELDS or
            event.get("repair_verified") is not True or
            type(event.get("repair_index")) is not int or
            event["repair_index"] != chunk["index"] or
            type(event.get("cipher_bytes")) is not int or
            event["cipher_bytes"] != chunk["cipher_bytes"] or
            event.get("file_id") != body["file_id"] or
            event.get("manifest_sha256") != digest or
            event.get("repair_transport") != REPAIR_TRANSPORT):
        raise PlaybackError("S15 reported an invalid/mismatched MoQ repair")
    # A local process' success JSON is not proof: authenticate CAS and all
    # exact signed S1 chunks again before any authorised seek/decrypt.
    _read_verified_chunk(target, chunk)
    verify_package(signed_manifest, target, trusted_artist)
    return {"repair_complete": True, "recovered_objects": 1,
            "repair_index": chunk["index"],
            "reused_objects": len(body["chunks"]) - 1,
            "total_objects": len(body["chunks"]), "manifest_sha256": digest,
            "repair_transport": REPAIR_TRANSPORT}
