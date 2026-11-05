"""S9: bind a real Holochain-author-authenticated host MoQ endpoint to S1.

No JSON from a third-party peer is accepted as provenance. Only a trusted
local conductor app and two *independently supplied* DNA pins anchor records.
The endpoint URL/certificate pin comes from the host-authored S2 entry, never
from the publisher's local readiness file. Only ciphertext crosses MoQ.
"""
from __future__ import annotations

import json
from ipaddress import IPv4Address, IPv4Network, AddressValueError
import os
import select
import time
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Callable
from urllib.parse import urlsplit

from holochain_storage.holochain_identity import (
    HOST_PURPOSE, OWNER_PURPOSE, key_for_agent,
    verify_owned_manifest, verify_replica_claim,
)
from holochain_storage.network_client import ReadOnlyStorageNodeClient
from holochain_storage.package import (
    StorageError, canonical, verify_package, _read_verified_chunk,
)
from .contract import verify_track_manifest
from .live_conductor import ConductorBridgeError, _record

MOQ_BRIDGE_SCHEMA = "holochain-music/conductor-moq-read/v1"
MOQ_ENDPOINT_SCHEMA = "holochain-storage/moq-endpoint/v1"
EXPECTED_KEYS = {
    "schema", "app_id", "reader_agent", "catalogue_dna", "storage_dna",
    "track", "owner_key_binding", "owner_commitment", "node_key_binding",
    "replica_claim", "moq_endpoint",
}
HEX = frozenset("0123456789abcdef")


def _receive_verified_progress(
    argv: list[str], signed_manifest: dict, store: Path,
    on_chunk: Callable[[int], None], timeout: int,
) -> dict:
    """Consume bounded JSONL from trusted local MoQ CLI with per-CAS hash checks.

    stdout progress is merely a notification; the listener re-hashes the
    signed-manifest object from its CAS BEFORE releasing each chunk to S12.
    No untrusted readiness URL, key, plaintext or audio is present here.
    """
    chunks = signed_manifest["body"]["chunks"]
    argv = [*argv, "--progress-jsonl"]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                bufsize=0)
    except OSError as exc:
        raise ConductorBridgeError("cannot start pinned MoQ progress receiver") from exc
    expected = 0
    end: dict | None = None
    pending = bytearray()
    total_stdout = 0
    deadline = time.monotonic() + timeout
    try:
        assert proc.stdout is not None
        while end is None:
            remaining = min(deadline - time.monotonic(), 30.0)
            if remaining <= 0:
                raise ConductorBridgeError("MoQ progress timed out")
            readable, _, _ = select.select([proc.stdout], [], [], remaining)
            if not readable:
                raise ConductorBridgeError("MoQ chunk progress stalled")
            data = os.read(proc.stdout.fileno(), 4096)
            if not data:
                raise ConductorBridgeError("MoQ terminated without transfer-complete event")
            total_stdout += len(data)
            if total_stdout > len(chunks) * 512 + 4096:
                raise ConductorBridgeError("oversized MoQ progress channel")
            pending.extend(data)
            if len(pending) > 8192 and b"\n" not in pending:
                raise ConductorBridgeError("oversized MoQ event")
            while b"\n" in pending:
                line, _, rest = pending.partition(b"\n")
                pending = bytearray(rest)
                if len(line) > 4096:
                    raise ConductorBridgeError("oversized MoQ event line")
                try:
                    event = json.loads(line)
                except (UnicodeError, ValueError) as exc:
                    raise ConductorBridgeError("non-JSON MoQ progress event") from exc
                if not isinstance(event, dict):
                    raise ConductorBridgeError("invalid MoQ progress event")
                if event.get("kind") == "chunk_verified":
                    if (set(event) != {"kind", "index", "sha256", "cipher_bytes"} or
                            expected >= len(chunks)):
                        raise ConductorBridgeError("unexpected MoQ chunk progress")
                    chunk = chunks[expected]
                    if (type(event["index"]) is not int or event["index"] != expected or
                            event["sha256"] != chunk["sha256"] or
                            type(event["cipher_bytes"]) is not int or
                            event["cipher_bytes"] != chunk["cipher_bytes"]):
                        raise ConductorBridgeError("out-of-order or forged MoQ chunk report")
                    # Independently verify that the object was atomically
                    # stored by the receiver, not just announced on stdout.
                    _read_verified_chunk(store, chunk)
                    on_chunk(expected)
                    expected += 1
                elif event.get("kind") == "transfer_complete":
                    if expected != len(chunks) or set(event) != {
                        "kind", "verified", "received_chunks", "cipher_bytes",
                        "manifest_sha256", "file_id",
                    }:
                        raise ConductorBridgeError("MoQ completed before all signed chunks")
                    end = {k: v for k, v in event.items() if k != "kind"}
                    if pending:
                        raise ConductorBridgeError("MoQ emitted output after complete event")
                    break
                else:
                    raise ConductorBridgeError("unknown MoQ progress event kind")
        # A success line is not enough; the QUIC receiver must exit cleanly.
        remaining = deadline - time.monotonic()
        if remaining <= 0 or proc.wait(timeout=remaining) != 0:
            raise ConductorBridgeError("MoQ receiver failed after progress event")
        return end
    except subprocess.TimeoutExpired as exc:
        raise ConductorBridgeError("MoQ process did not terminate") from exc
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        if proc.stdout:
            proc.stdout.close()



def _pin(label: str, value: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 200 or "\x00" in value:
        raise ConductorBridgeError(f"invalid {label}")


def _hex(label: str, value: Any, length: int = 64) -> None:
    if not isinstance(value, str) or len(value) != length or any(c not in HEX for c in value):
        raise ConductorBridgeError(f"invalid {label}")


RFC1918 = (IPv4Network("10.0.0.0/8"), IPv4Network("172.16.0.0/12"),
           IPv4Network("192.168.0.0/16"))


def _bound_local_url(value: Any, *, allow_lan: bool = False) -> str:
    """Reject DNS, userinfo and public endpoints even in opt-in LAN mode.

    The URL must still come from Carol's authenticated Holochain S2 action,
    and the certificate fingerprint remains pinned independently. No host
    readiness JSON or untrusted DNS value can promote a remote connection.
    """
    if type(allow_lan) is not bool or not isinstance(value, str) or len(value) > 80:
        raise ConductorBridgeError("invalid host MoQ URL/allow_lan")
    try:
        u = urlsplit(value)
        if (u.scheme != "https" or u.username is not None or
                u.password is not None or u.port is None or
                not 1 <= u.port <= 65535 or u.path or u.query or u.fragment or
                not u.hostname or value != f"https://{u.hostname}:{u.port}"):
            raise ConductorBridgeError("MoQ endpoint must be canonical HTTPS IPv4:port")
        if u.hostname != "127.0.0.1":
            try:
                addr = IPv4Address(u.hostname)
            except AddressValueError as exc:
                raise ConductorBridgeError("MoQ LAN endpoint must use a literal IPv4 address") from exc
            if not allow_lan or not any(addr in network for network in RFC1918):
                raise ConductorBridgeError("remote MoQ requires explicit RFC1918 LAN opt-in")
    except ValueError as exc:
        raise ConductorBridgeError("malformed MoQ URL") from exc
    return value


def receive_moq_from_live_conductor(
    *, bridge_binary: str | Path, moq_binary: str | Path, admin_port: int,
    app_id: str, catalogue_dna: str, storage_dna: str, reader_agent: str,
    artist_agent: str, node_agent: str, track_id: str, storage_url: str,
    target_store: str | Path, catalogue_role: str = "music_catalogue",
    storage_role: str = "music_storage", timeout: int = 120,
    reader: ReadOnlyStorageNodeClient | None = None,
    include_trust_context: bool = False,
    on_trusted_manifest: Callable[[dict, bytes, str, str], None] | None = None,
    on_verified_chunk: Callable[[int], None] | None = None,
    allow_lan_moq: bool = False,
) -> dict:
    """Retrieve and verify a finite encrypted music package over pinned MoQ.

    1. Authenticate Bob's *local* Holochain app, role→DNA hashes and agent.
    2. Read real DHT-authored S5/S2 artist, file, host, MoQ endpoint records.
    3. Fetch S1 manifest & S4 receipt (not ciphertext) and verify signer,
       catalogue digest, file commitment, receipt and replica claim.
    4. Give MoQ CLI only the DHT-derived URL/certificate fingerprint and
       independently verified artist signing key, manifest digest and file.
    5. Verify every received ciphertext chunk against the signed S1 manifest.

    No plaintext, content key, artist private key or host signing secret goes
    to Holochain, MoQ, or the S4 server. A test-only reader may be injected;
    production must use ReadOnlyStorageNodeClient. Admin WebSocket localhost.
    """
    bridge, moq = Path(bridge_binary).expanduser(), Path(moq_binary).expanduser()
    if any(not p.is_absolute() or not p.is_file() for p in (bridge, moq)):
        raise ConductorBridgeError("trusted bridge and MoQ binaries must be existing absolute files")
    if type(admin_port) is not int or not 1 <= admin_port <= 65535:
        raise ConductorBridgeError("invalid local Holochain admin port")
    if type(timeout) is not int or not 1 <= timeout <= 300:
        raise ConductorBridgeError("invalid timeout")
    if type(allow_lan_moq) is not bool:
        raise ConductorBridgeError("allow_lan_moq must be a boolean")
    for label, value in (
        ("app ID", app_id), ("catalogue DNA", catalogue_dna),
        ("storage DNA", storage_dna), ("reader agent", reader_agent),
        ("artist agent", artist_agent), ("node agent", node_agent),
        ("catalogue role", catalogue_role), ("storage role", storage_role),
    ):
        _pin(label, value)
    _hex("track ID", track_id, 32)
    if catalogue_dna == storage_dna:
        raise ConductorBridgeError("two distinct trusted DNA pins are required")
    argv = [str(bridge), "--admin", f"127.0.0.1:{admin_port}",
            "--app-id", app_id, "--catalogue-role", catalogue_role,
            "--storage-role", storage_role,
            "--expect-catalogue-dna", catalogue_dna,
            "--expect-storage-dna", storage_dna,
            "--artist", artist_agent, "--node", node_agent,
            "--track-id", track_id, "--include-moq-endpoint", "true"]
    try:
        completed = subprocess.run(argv, text=True, capture_output=True,
                                   timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ConductorBridgeError("unable to query trusted local conductor") from exc
    if completed.returncode or len(completed.stdout.encode("utf-8")) > 1_000_000:
        raise ConductorBridgeError("Holochain MoQ bridge refused lookup")
    try:
        reply = json.loads(completed.stdout)
    except ValueError as exc:
        raise ConductorBridgeError("invalid Holochain MoQ response") from exc
    if not isinstance(reply, dict) or set(reply) != EXPECTED_KEYS or reply.get("schema") != MOQ_BRIDGE_SCHEMA:
        raise ConductorBridgeError("unexpected Holochain MoQ bridge schema")
    for field, pinned in (("app_id", app_id), ("catalogue_dna", catalogue_dna),
                          ("storage_dna", storage_dna), ("reader_agent", reader_agent)):
        if reply[field] != pinned:
            raise ConductorBridgeError(f"Holochain {field} does not match trusted pin")
    track = _record(reply["track"])
    owner_key = _record(reply["owner_key_binding"])
    owner_commitment = _record(reply["owner_commitment"])
    node_key = _record(reply["node_key_binding"])
    claim = _record(reply["replica_claim"])
    endpoint = _record(reply["moq_endpoint"])
    if any(r.author != artist_agent for r in (track, owner_key, owner_commitment)) or any(
        r.author != node_agent for r in (node_key, claim, endpoint)
    ):
        raise ConductorBridgeError("Holochain action author mismatch")
    if track.body.get("track_id") != track_id or track.body.get("artist_agent") != artist_agent:
        raise ConductorBridgeError("incorrect artist/track from Holochain")
    file_id, digest = track.body.get("file_id"), track.body.get("manifest_sha256")
    _hex("file ID", file_id)
    _hex("S1 manifest SHA-256", digest)
    expected_endpoint = {"schema": MOQ_ENDPOINT_SCHEMA, "node_agent": node_agent,
                         "owner_agent": artist_agent, "file_id": file_id,
                         "manifest_sha256": digest}
    body = endpoint.body
    if set(body) != (set(expected_endpoint) | {"url", "cert_fingerprint_hex"}) or any(
        body.get(k) != v for k, v in expected_endpoint.items()
    ):
        raise ConductorBridgeError("MoQ endpoint does not bind the exact host/file/manifest")
    moq_url = _bound_local_url(body["url"], allow_lan=allow_lan_moq)
    _hex("MoQ certificate fingerprint", body["cert_fingerprint_hex"])
    # The signed manifest/receipt are public. Do not fetch ciphertext through
    # HTTP: MoQ must be the only path that transfers ciphertext for this test.
    storage = reader if reader is not None else ReadOnlyStorageNodeClient(storage_url)
    signed_manifest = storage.manifest(file_id)
    artist_public = key_for_agent(owner_key, artist_agent, OWNER_PURPOSE)
    host_public = key_for_agent(node_key, node_agent, HOST_PURPOSE)
    track_body = verify_track_manifest(track.body, signed_manifest,
                                       author=artist_agent, trusted_signer=artist_public)
    owned = verify_owned_manifest(signed_manifest, artist_agent, owner_key, owner_commitment)
    if owned != track_body:
        raise StorageError("catalogue and owner commitment do not agree")
    receipt = storage.receipt(signed_manifest)
    verify_replica_claim(receipt, signed_manifest, artist_agent, node_agent,
                         owner_key, node_key, owner_commitment, claim)
    # S12: only reveal independently authenticated S1 and Holochain public
    # pins to the local authorised player; no MoQ connection exists yet.
    if on_trusted_manifest is not None:
        on_trusted_manifest(signed_manifest, artist_public, artist_agent, reader_agent)
    with tempfile.TemporaryDirectory(prefix="holochain-music-s9-manifest-") as directory:
        signed_path = Path(directory) / "signed-manifest.json"
        signed_path.write_bytes(canonical(signed_manifest))
        recv = [str(moq), "receive", "--manifest", str(signed_path),
                "--store", str(Path(target_store)),
                "--trusted-artist-hex", artist_public.hex(),
                "--expected-manifest-sha256", digest,
                "--url", moq_url,
                "--cert-fingerprint-hex", body["cert_fingerprint_hex"]]
        if allow_lan_moq and not moq_url.startswith("https://127.0.0.1:"):
            recv.append("--allow-lan")
        if on_verified_chunk is not None:
            report = _receive_verified_progress(recv, signed_manifest,
                                                Path(target_store),
                                                on_verified_chunk, timeout)
        else:
            # Backwards compatible S9-S11 synchronous completion behaviour.
            try:
                result = subprocess.run(recv, capture_output=True, text=True,
                                        timeout=timeout, check=False)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise ConductorBridgeError("MoQ ciphertext transfer failed") from exc
            if result.returncode or len(result.stdout.encode("utf-8")) > 4096:
                raise ConductorBridgeError("pinned MoQ ciphertext transfer rejected or incomplete")
            try:
                report = json.loads(result.stdout)
            except ValueError as exc:
                raise ConductorBridgeError("invalid MoQ ciphertext report") from exc
    if not isinstance(report, dict) or set(report) != {
        "verified", "received_chunks", "cipher_bytes", "manifest_sha256", "file_id"
    } or report["verified"] is not True or report["file_id"] != file_id or (
        report["manifest_sha256"] != digest or
        report["received_chunks"] != len(signed_manifest["body"]["chunks"])
    ):
        raise ConductorBridgeError("MoQ output mismatched the trusted manifest")
    # Defence in depth: don't trust a child process' success JSON alone.
    verify_package(signed_manifest, Path(target_store), artist_public)
    if include_trust_context:
        # S10 owner-grant verifier must use the SAME owner signing key and
        # Bob agent that the trusted, DNA-pinned conductor authenticated.
        # Only public metadata leaves this function: NEVER a content key.
        return {**report, "verified_owner_key_hex": artist_public.hex(),
                "verified_reader_agent": reader_agent,
                "verified_owner_agent": artist_agent,
                "verified_node_key_hex": host_public.hex(),
                "verified_node_agent": node_agent,
                "verified_moq_url": moq_url,
                "verified_moq_cert_fingerprint_hex": body["cert_fingerprint_hex"]}
    return report
