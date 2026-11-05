"""Fetch live S5/S2 records through Bob's authenticated local Holochain conductor.

The companion Rust `music_conductor_bridge` opens an authenticated Holochain
0.7 app WebSocket, requires exact DNA pins and matching cell agent keys,
and returns data from the installed, validated coordinator zomes. This module
NEVER treats a third-party JSON document as evidence of DHT authorship.

Admin websocket credentials give broad authority. Run the Rust binary only
against a trusted conductor bound to localhost. Its stdout is a *local IPC*
result, not an exportable proof a remote party could independently verify.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from holochain_storage.holochain_identity import AuthoredRecord
from holochain_storage.network_client import ReadOnlyStorageNodeClient

from .contract import CatalogueError
from .verified_retrieval import fetch_verified_track

BRIDGE_SCHEMA = "holochain-music/conductor-read/v1"
_MAX_OUTPUT_BYTES = 1_000_000
_REQUIRED = {
    "schema", "app_id", "reader_agent", "catalogue_dna", "storage_dna",
    "track", "owner_key_binding", "owner_commitment", "node_key_binding", "replica_claim",
}
_RECORD_FIELDS = {"author", "action_hash", "body"}


class ConductorBridgeError(CatalogueError):
    """Local conductor is unreachable or returned an untrusted/ambiguous view."""


def _record(value: Any) -> AuthoredRecord:
    if (not isinstance(value, dict) or set(value) != _RECORD_FIELDS
            or not isinstance(value["author"], str) or not value["author"]
            or not isinstance(value["action_hash"], str) or not value["action_hash"]
            or not isinstance(value["body"], dict)):
        raise ConductorBridgeError("malformed conductor-authored record")
    return AuthoredRecord(author=value["author"], action_hash=value["action_hash"], body=value["body"])


def fetch_from_live_conductor(
    *,
    bridge_binary: str | Path,
    admin_port: int,
    app_id: str,
    catalogue_dna: str,
    storage_dna: str,
    reader_agent: str,
    artist_agent: str,
    node_agent: str,
    track_id: str,
    storage_url: str,
    target_store: str | Path,
    signed_manifest: dict | None = None,
    catalogue_role: str = "music_catalogue",
    storage_role: str = "music_storage",
    timeout: int = 120,
    reader: ReadOnlyStorageNodeClient | None = None,
) -> dict:
    """Query Bob's conductor and download only the authenticated ciphertext.

    When omitted, the untrusted S4 signed manifest is fetched by its S5 file
    ID and verified against the pinned S5+S2 digest and artist Ed25519 key.
    The S4 node is not given any decryption key. The explicit reader_agent and
    DNA hashes must be pinned before the bridge starts: don't obtain them
    from the bridge output itself and call that authentication.

    A custom ``reader`` is for tests; production should let this function
    instantiate a real ReadOnlyStorageNodeClient.
    """
    executable = Path(bridge_binary).expanduser()
    if not executable.is_absolute() or not executable.is_file():
        raise ConductorBridgeError("bridge_binary must be an existing absolute path to trusted code")
    if type(admin_port) is not int or not 1 <= admin_port <= 65535:
        raise ConductorBridgeError("invalid local admin WebSocket port")
    if type(timeout) is not int or not 1 <= timeout <= 300:
        raise ConductorBridgeError("invalid timeout")
    for label, value in (
        ("app ID", app_id), ("catalogue DNA pin", catalogue_dna),
        ("storage DNA pin", storage_dna), ("reader agent", reader_agent),
        ("artist agent", artist_agent), ("node agent", node_agent),
        ("catalogue role", catalogue_role), ("storage role", storage_role),
        ("track ID", track_id),
    ):
        if not isinstance(value, str) or not value or len(value) > 200 or "\x00" in value:
            raise ConductorBridgeError(f"invalid {label}")
    if catalogue_dna == storage_dna:
        raise ConductorBridgeError("two independent DNA pins are required")
    if (len(track_id) != 32 or any(ch not in "0123456789abcdef" for ch in track_id)):
        raise ConductorBridgeError("invalid track ID")

    argv = [
        str(executable), "--admin", f"127.0.0.1:{admin_port}",
        "--app-id", app_id,
        "--catalogue-role", catalogue_role,
        "--storage-role", storage_role,
        "--expect-catalogue-dna", catalogue_dna,
        "--expect-storage-dna", storage_dna,
        "--artist", artist_agent,
        "--node", node_agent,
        "--track-id", track_id,
    ]
    try:
        completed = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConductorBridgeError("unable to query trusted local Holochain conductor") from exc
    if completed.returncode != 0:
        # Do not put arbitrary remote error strings into the user interface.
        raise ConductorBridgeError("Holochain conductor bridge refused the lookup")
    if len(completed.stdout.encode("utf-8")) > _MAX_OUTPUT_BYTES:
        raise ConductorBridgeError("oversized Holochain record response")
    try:
        output = json.loads(completed.stdout)
    except (TypeError, ValueError) as exc:
        raise ConductorBridgeError("non-JSON conductor response") from exc
    if not isinstance(output, dict) or set(output) != _REQUIRED or output["schema"] != BRIDGE_SCHEMA:
        raise ConductorBridgeError("unexpected Holochain bridge schema")
    for name, pinned in (
        ("app_id", app_id), ("catalogue_dna", catalogue_dna),
        ("storage_dna", storage_dna), ("reader_agent", reader_agent),
    ):
        if output[name] != pinned:
            raise ConductorBridgeError(f"Holochain bridge {name} mismatch")
    track = _record(output["track"])
    owner_key = _record(output["owner_key_binding"])
    commitment = _record(output["owner_commitment"])
    node_key = _record(output["node_key_binding"])
    claim = _record(output["replica_claim"])
    if (track.author != artist_agent or owner_key.author != artist_agent
            or commitment.author != artist_agent
            or node_key.author != node_agent or claim.author != node_agent):
        raise ConductorBridgeError("Holochain record action author mismatch")
    if track.body.get("track_id") != track_id:
        raise ConductorBridgeError("wrong track returned by Holochain")

    node_reader = reader if reader is not None else ReadOnlyStorageNodeClient(storage_url)
    if signed_manifest is None:
        file_id = track.body.get("file_id")
        if (not isinstance(file_id, str) or len(file_id) != 64
                or any(c not in "0123456789abcdef" for c in file_id)):
            raise ConductorBridgeError("invalid Holochain-pinned file ID")
        signed_manifest = node_reader.manifest(file_id)
    return fetch_verified_track(
        track_record=track,
        signed_manifest=signed_manifest,
        owner_key_binding=owner_key,
        owner_commitment=commitment,
        node_agent=node_agent,
        node_key_binding=node_key,
        replica_claim=claim,
        reader=node_reader,
        target_store=target_store,
    )
