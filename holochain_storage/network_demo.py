"""End-to-end demo against a locally running Rust storage node.

Use: python -m holochain_storage.network_demo path/to/file --node http://127.0.0.1:4780
Run the Rust node with the artist public key printed by --new-key first.
"""
import argparse
import base64
import hashlib
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .network_client import StorageNodeClient
from .package import create_package, decrypt_package, public_key_bytes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    parser.add_argument("--node", default="http://127.0.0.1:4780")
    parser.add_argument("--node-key", required=True, help="base64 Ed25519 key printed by node")
    parser.add_argument("--artist-secret", required=True, help="path to existing 32-byte raw Ed25519 key (demo only)")
    args = parser.parse_args()
    private_key = Ed25519PrivateKey.from_private_bytes(args.artist_secret.read_bytes())
    trusted_node = base64.b64decode(args.node_key, validate=True)
    with tempfile.TemporaryDirectory(prefix="holochain-storage-network-demo-") as d:
        root = Path(d)
        package, content_key = create_package(args.file, root / "artist", private_key)
        client = StorageNodeClient(args.node, private_key)
        client.upload(package, root / "artist")
        client.commit(package, trusted_node)
        client.fetch(package, root / "buyer", trusted_node)
        output = decrypt_package(package, root / "buyer", root / "recovered.dat", content_key, public_key_bytes(private_key))
        if hashlib.sha256(output.read_bytes()).digest() != hashlib.sha256(args.file.read_bytes()).digest():
            raise AssertionError("downloaded file differs")
        print("OK: storage node accepted complete encrypted replica and signed S1 receipt")
        print("OK: all chunks downloaded, verified, and decrypted back to identical original file")


if __name__ == "__main__":
    main()
