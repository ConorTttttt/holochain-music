"""Ephemeral Model-A demo: temporary scratch data is removed on normal exit.

Usage: python -m holochain_storage.demo path/to/any/file

This is a local, two-replica protocol demo, not networked proof of storage or
payment processing. Key generation/recipient identity are demonstrative only.
"""

from __future__ import annotations

import argparse
import hashlib
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .grant import create_perpetual_grant, open_perpetual_grant
from .package import (
    StorageError, create_package, decrypt_package, replicate_package,
    verify_package, verify_receipt,
)


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify local encrypted full replicas and a buyer's offline recovery. No network involved."
    )
    parser.add_argument("file", type=Path, help="Any file (music, document, image, etc.)")
    args = parser.parse_args()
    if not args.file.is_file():
        parser.error("file must exist")

    artist = Ed25519PrivateKey.generate()
    artist_pub = artist.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    buyer = X25519PrivateKey.generate()
    buyer_pub = buyer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    first_node, second_node = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(prefix="holochain-storage-demo-") as scratch:
        base = Path(scratch)
        signed_manifest, secret = create_package(args.file, base / "owner", artist)
        verified_nodes = 0
        for i, node in enumerate((first_node, second_node), start=1):
            replica = base / f"node-{i}"
            receipt = replicate_package(signed_manifest, base / "owner", replica, artist_pub, node)
            node_pub = node.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            verify_receipt(receipt, signed_manifest, node_pub, artist_pub)
            verify_package(signed_manifest, replica, artist_pub)
            verified_nodes += 1

        grant = create_perpetual_grant(signed_manifest, artist_pub, artist, secret, buyer_pub)
        unwrapped = open_perpetual_grant(grant, signed_manifest, artist_pub, buyer)
        recovered = decrypt_package(signed_manifest, base / "node-2", base / "recovered", unwrapped, artist_pub)
        if _file_sha256(recovered) != _file_sha256(args.file):
            raise StorageError("offline recovery produced different bytes")

        print(f"OK: {verified_nodes} complete encrypted replicas and matching signed receipts")
        print("OK: buyer grant decrypted and original file reconstructed byte-for-byte")
        print("Temporary scratch files removed on exit (not securely erased); no network, payment or custody proof")


if __name__ == "__main__":
    main()
