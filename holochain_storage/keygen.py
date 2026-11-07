"""Generate a local Ed25519 artist key for S4 development ONLY.

Do not use this ad hoc file key manager for production accounts.
Usage: python -m holochain_storage.keygen --out ./dev-artist.key
"""
import argparse
import base64
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    private = Ed25519PrivateKey.generate()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(private.private_bytes_raw())
        f.flush()
        os.fsync(f.fileno())
    pub = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    print("artist Ed25519 public key:", base64.b64encode(pub).decode())
    print("private key path:", args.out, "(NEVER commit this file)")


if __name__ == "__main__":
    main()
