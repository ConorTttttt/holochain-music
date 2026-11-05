"""S7 test-only local S1/S4 fixture and Bob's real conductor-to-ciphertext download.

Three invocations are coordinated by a Rust Sweettest holding Alice/Bob's
actual Holochain conductors and a real S4 storage-node child process:
  prepare -> upload -> download
No mocked Holochain records are accepted in the download phase. The test-only
AES content key and artist signing private key remain on the local test
workspace and are never passed to the Rust node, conductor, or bridge.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from holochain_storage.network_client import StorageNodeClient
from holochain_storage.package import (
    canonical, create_package, decrypt_package, manifest_digest, public_key_bytes,
    sha256, verify_package,
)
from music_catalogue.live_conductor import fetch_from_live_conductor


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _load(root: Path) -> dict:
    return json.loads((root / "fixture.json").read_text())


def prepare(root: Path) -> dict:
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    artist = Ed25519PrivateKey.generate()
    _write_private(root / "artist.ed25519", artist.private_bytes_raw())
    # Synthetic opaque audio bytes; this is NOT a real FLAC decoder test.
    sample = (b"S7 synthetic opaque audio test fixture - " * 1024) + os.urandom(4096)
    (root / "sample.flac").write_bytes(sample)
    manifest, secret = create_package(root / "sample.flac", root / "alice-store", artist, chunk_size=4096)
    _write_private(root / "content.key", secret)
    (root / "manifest.json").write_bytes(canonical(manifest))
    pub = public_key_bytes(artist)
    fixture = {
        "artist_public_hex": pub.hex(),
        "artist_public_b64": base64.b64encode(pub).decode("ascii"),
        "file_id": manifest["body"]["file_id"],
        "manifest_sha256": manifest_digest(manifest),
        "track_id": os.urandom(16).hex(),
        "sample_sha256": sha256(sample),
    }
    (root / "fixture.json").write_bytes(canonical(fixture))
    return fixture


def upload(root: Path, node_url: str, node_root: Path) -> dict:
    fixture = _load(root)
    owner = Ed25519PrivateKey.from_private_bytes((root / "artist.ed25519").read_bytes())
    manifest = json.loads((root / "manifest.json").read_text())
    # This reads the test node's local keystore ONLY to determine its public
    # key. The node private key is never included in DHT records or requests.
    node_private = Ed25519PrivateKey.from_private_bytes((node_root / "node.ed25519").read_bytes())
    host_public = public_key_bytes(node_private)
    client = StorageNodeClient(node_url, owner)
    client.upload(manifest, root / "alice-store")
    receipt = client.commit(manifest, host_public)
    (root / "receipt.json").write_bytes(canonical(receipt))
    public_receipt = {
        "node_public_hex": host_public.hex(),
        "receipt_sha256": sha256(canonical(receipt)),
        "file_id": fixture["file_id"],
        "manifest_sha256": fixture["manifest_sha256"],
    }
    return public_receipt


def download(
    root: Path, node_url: str, bridge_binary: Path, admin_port: int, app_id: str,
    catalogue_dna: str, storage_dna: str, reader_agent: str,
    artist_agent: str, node_agent: str, track_id: str,
    catalogue_role: str, storage_role: str,
) -> dict:
    fixture = _load(root)
    assert track_id == fixture["track_id"], "test requested wrong track"
    # Important: NO signed_manifest argument, NO AuthoredRecord fixtures.
    # The Rust bridge must obtain validated S5/S2 records from Bob's conductor,
    # and Python must fetch S4's untrusted manifest by the pinned file ID.
    body = fetch_from_live_conductor(
        bridge_binary=bridge_binary, admin_port=admin_port, app_id=app_id,
        catalogue_dna=catalogue_dna, storage_dna=storage_dna,
        reader_agent=reader_agent, artist_agent=artist_agent, node_agent=node_agent,
        track_id=track_id, storage_url=node_url, target_store=root / "bob-store",
        catalogue_role=catalogue_role, storage_role=storage_role,
    )
    assert body["file_id"] == fixture["file_id"], "downloaded wrong encrypted package"
    manifest = json.loads((root / "manifest.json").read_text())
    assert manifest_digest(manifest) == fixture["manifest_sha256"]
    artist_pub = bytes.fromhex(fixture["artist_public_hex"])
    verify_package(manifest, root / "bob-store", artist_pub)
    # The content key is test-only: this roundtrip assertion is not a claim
    # that every listener has a decryption entitlement or key grant.
    recovered = decrypt_package(
        manifest, root / "bob-store", root / "recovered.flac",
        (root / "content.key").read_bytes(), artist_pub,
    )
    assert sha256(recovered.read_bytes()) == fixture["sample_sha256"], "ciphertext roundtrip mismatch"
    return {"file_id": body["file_id"], "sha256": sha256(recovered.read_bytes()),
            "ciphertext_chunks": len(body["chunks"]), "verified": True}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("prepare", "upload", "download"))
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--node-url")
    parser.add_argument("--node-root", type=Path)
    parser.add_argument("--bridge-binary", type=Path)
    parser.add_argument("--admin-port", type=int)
    parser.add_argument("--app-id")
    parser.add_argument("--catalogue-dna")
    parser.add_argument("--storage-dna")
    parser.add_argument("--reader-agent")
    parser.add_argument("--artist-agent")
    parser.add_argument("--node-agent")
    parser.add_argument("--track-id")
    parser.add_argument("--catalogue-role")
    parser.add_argument("--storage-role")
    args = parser.parse_args()
    if args.stage == "prepare":
        result = prepare(args.root)
    elif args.stage == "upload":
        if args.node_url is None or args.node_root is None:
            parser.error("upload requires --node-url and --node-root")
        result = upload(args.root, args.node_url, args.node_root)
    else:
        required = ("node_url", "bridge_binary", "admin_port", "app_id",
                    "catalogue_dna", "storage_dna", "reader_agent", "artist_agent",
                    "node_agent", "track_id", "catalogue_role", "storage_role")
        if any(getattr(args, k) is None for k in required):
            parser.error("download requires all conductor, role and storage parameters")
        result = download(
            args.root, args.node_url, args.bridge_binary, args.admin_port, args.app_id,
            args.catalogue_dna, args.storage_dna, args.reader_agent, args.artist_agent,
            args.node_agent, args.track_id, args.catalogue_role, args.storage_role,
        )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
