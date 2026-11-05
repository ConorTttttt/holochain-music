"""Model-A encrypted packages: full replicas of signed, opaque encrypted chunks.

Cryptographic prototype, NOT a deployed storage network. No network transfer,
Holochain identity binding, payment verification, or proof of ongoing custody.
The 32-byte content key is returned to the caller; it is NEVER saved in the
public manifest, chunk store, or storage receipt.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SCHEMA = "holochain-storage/encrypted-package/v1"
RECEIPT_SCHEMA = "holochain-storage/replica-receipt/v1"
CHUNK_BYTES = 256 * 1024
MAX_CHUNK_BYTES = 4 * 1024 * 1024
# Enforce a bounded v1 manifest and file size before allocating/copying data.
# Larger files will require an explicit, reviewed schema/version change.
MAX_CHUNKS = 16_384
MAX_FILE_BYTES = 64 * 1024**3
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


class StorageError(ValueError):
    """A signed package, chunk, or receipt failed verification."""


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def from_b64(text: str, size: int | None = None) -> bytes:
    if not isinstance(text, str):
        raise StorageError("invalid base64 field")
    try:
        value = base64.b64decode(text, validate=True)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise StorageError("invalid base64 field") from exc
    if size is not None and len(value) != size:
        raise StorageError("invalid encoded field length")
    return value


def public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise StorageError("invalid sha256 digest")
    return value


def object_path(root: str | Path, digest: str) -> Path:
    digest = _digest(digest)
    return Path(root) / "objects" / "sha256" / digest[:2] / digest


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".incoming-", delete=False) as f:
            temp = f.name
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
        temp = None
    finally:
        if temp:
            Path(temp).unlink(missing_ok=True)


def _store_chunk(root: Path, payload: bytes) -> str:
    digest = sha256(payload)
    destination = object_path(root, digest)
    if destination.is_symlink():
        raise StorageError("refusing symlinked storage object")
    if destination.exists():
        if not destination.is_file() or destination.stat().st_size != len(payload) or sha256(destination.read_bytes()) != digest:
            raise StorageError(f"corrupt existing object: {digest}")
    else:
        _atomic_write(destination, payload)
    return digest


def _aad(file_id: str, index: int) -> bytes:
    return b"holochain-storage/chunk/v1\x00" + bytes.fromhex(file_id) + struct.pack(">Q", index)


def _assert_manifest(manifest: Any) -> None:
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema", "file_id", "cipher", "chunk_size", "total_plain_bytes", "chunks"
    } or manifest["schema"] != SCHEMA or manifest["cipher"] != "AES-256-GCM":
        raise StorageError("invalid package schema")
    _digest(manifest["file_id"])
    chunk_size, total, chunks = manifest["chunk_size"], manifest["total_plain_bytes"], manifest["chunks"]
    if type(chunk_size) is not int or not 1 <= chunk_size <= MAX_CHUNK_BYTES:
        raise StorageError("invalid chunk size")
    if type(total) is not int or not 0 <= total <= MAX_FILE_BYTES:
        raise StorageError("invalid package length")
    if not isinstance(chunks, list) or len(chunks) > MAX_CHUNKS or (not chunks and total != 0):
        raise StorageError("invalid number of package chunks")
    running_total = 0
    seen_nonces: set[bytes] = set()
    for i, chunk in enumerate(chunks):
        if not isinstance(chunk, dict) or set(chunk) != {"index", "sha256", "cipher_bytes", "plain_bytes", "nonce"}:
            raise StorageError("invalid chunk structure")
        if type(chunk["index"]) is not int or chunk["index"] != i:
            raise StorageError("invalid chunk index")
        _digest(chunk["sha256"])
        n = from_b64(chunk["nonce"], 12)
        if n in seen_nonces:
            raise StorageError("nonce reused in package")
        seen_nonces.add(n)
        plain_len, cipher_len = chunk["plain_bytes"], chunk["cipher_bytes"]
        if type(plain_len) is not int or not 1 <= plain_len <= chunk_size:
            raise StorageError("invalid plaintext chunk size")
        if type(cipher_len) is not int or cipher_len != plain_len + 16:
            raise StorageError("invalid ciphertext length")
        if i < len(chunks) - 1 and plain_len != chunk_size:
            raise StorageError("short nonfinal chunk")
        running_total += plain_len
    if running_total != total:
        raise StorageError("manifest length mismatch")


def _verify_signed(payload: dict[str, Any], trusted_signer: bytes, kind: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"body", "signer", "signature"}:
        raise StorageError(f"invalid signed {kind}")
    signer = from_b64(payload["signer"], 32)
    if not isinstance(trusted_signer, bytes) or len(trusted_signer) != 32 or signer != trusted_signer:
        raise StorageError(f"untrusted {kind} signer")
    try:
        body = canonical(payload["body"])
    except (InvalidSignature, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise StorageError(f"invalid {kind} signature") from exc
    if len(body) > MAX_MANIFEST_BYTES:
        raise StorageError(f"{kind} exceeds size limit")
    try:
        Ed25519PublicKey.from_public_bytes(signer).verify(from_b64(payload["signature"], 64), body)
    except (InvalidSignature, ValueError) as exc:
        raise StorageError(f"invalid {kind} signature") from exc
    if not isinstance(payload["body"], dict):
        raise StorageError(f"invalid {kind} body")
    return payload["body"]


def _sign(body: dict[str, Any], signer: Ed25519PrivateKey) -> dict[str, Any]:
    return {"body": body, "signer": b64(public_key_bytes(signer)), "signature": b64(signer.sign(canonical(body)))}


def manifest_digest(package: dict[str, Any]) -> str:
    return sha256(canonical(package))


def create_package(source: str | Path, store: str | Path, artist_key: Ed25519PrivateKey, *, chunk_size: int = CHUNK_BYTES) -> tuple[dict[str, Any], bytes]:
    """Encrypt an opaque file, including empty files. Return (signed manifest, secret content key).

    The caller MUST protect/back up the returned key and never send it to a host.
    """
    if type(chunk_size) is not int or not 1 <= chunk_size <= MAX_CHUNK_BYTES:
        raise StorageError("invalid chunk size")
    if not Path(source).is_file():
        raise StorageError("source file not found")
    if Path(source).stat().st_size > MAX_FILE_BYTES:
        raise StorageError("source file exceeds v1 size limit")
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    file_id = os.urandom(32).hex()
    root = Path(store)
    chunks: list[dict[str, Any]] = []
    total = 0
    with Path(source).open("rb") as f:
        while piece := f.read(chunk_size):
            index = len(chunks)
            if index >= MAX_CHUNKS or total + len(piece) > MAX_FILE_BYTES:
                raise StorageError("source file exceeds v1 manifest limits")
            nonce = os.urandom(12)
            encrypted = aes.encrypt(nonce, piece, _aad(file_id, index))
            digest = _store_chunk(root, encrypted)
            chunks.append({
                "index": index, "sha256": digest, "nonce": b64(nonce),
                "plain_bytes": len(piece), "cipher_bytes": len(encrypted),
            })
            total += len(piece)
    body = {
        "schema": SCHEMA, "file_id": file_id, "cipher": "AES-256-GCM",
        "chunk_size": chunk_size, "total_plain_bytes": total, "chunks": chunks,
    }
    _assert_manifest(body)
    if len(canonical(body)) > MAX_MANIFEST_BYTES:
        raise StorageError("manifest exceeds v1 size limit")
    return _sign(body, artist_key), key


def _read_verified_chunk(store: str | Path, chunk: dict[str, Any]) -> bytes:
    """Bound memory use and reject missing, truncated or tampered ciphertext."""
    path = object_path(store, chunk["sha256"])
    if path.is_symlink():
        raise StorageError(f"symlinked chunk {chunk['index']}")
    try:
        with path.open("rb") as stream:
            payload = stream.read(chunk["cipher_bytes"] + 1)
    except OSError as exc:
        raise StorageError(f"missing chunk {chunk['index']}") from exc
    if len(payload) != chunk["cipher_bytes"] or sha256(payload) != chunk["sha256"]:
        raise StorageError(f"corrupt chunk {chunk['index']}")
    return payload


def verify_package(package: dict[str, Any], store: str | Path, trusted_artist: bytes) -> dict[str, Any]:
    """Verify artist signature and every stored encrypted chunk; no decryption key needed."""
    body = _verify_signed(package, trusted_artist, "manifest")
    _assert_manifest(body)
    for chunk in body["chunks"]:
        _read_verified_chunk(store, chunk)
    return body


def replicate_package(package: dict[str, Any], source_store: str | Path, replica_store: str | Path,
                      trusted_artist: bytes, node_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Make a COMPLETE copy of all encrypted chunks and sign a receipt.

    A receipt asserts acceptance/verification at this instant. It is NOT proof
    that the node will retain the file or a future proof of retrievability.
    """
    body = verify_package(package, source_store, trusted_artist)
    source_store, replica_store = Path(source_store), Path(replica_store)
    for chunk in body["chunks"]:
        data = _read_verified_chunk(source_store, chunk)
        _store_chunk(replica_store, data)
    verify_package(package, replica_store, trusted_artist)
    receipt = {
        "schema": RECEIPT_SCHEMA, "file_id": body["file_id"],
        "manifest_sha256": manifest_digest(package),
        "chunk_count": len(body["chunks"]),
        "received_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    return _sign(receipt, node_key)


def verify_receipt(receipt: dict[str, Any], package: dict[str, Any], trusted_node: bytes, trusted_artist: bytes) -> dict[str, Any]:
    """Verify a storage receipt against the exact signed package and pinned node key."""
    body = _verify_signed(receipt, trusted_node, "receipt")
    manifest_body = _verify_signed(package, trusted_artist, "manifest")
    _assert_manifest(manifest_body)
    if not isinstance(body, dict) or set(body) != {"schema", "file_id", "manifest_sha256", "chunk_count", "received_at"}:
        raise StorageError("invalid receipt format")
    if body["schema"] != RECEIPT_SCHEMA or body["file_id"] != manifest_body["file_id"] or body["manifest_sha256"] != manifest_digest(package):
        raise StorageError("receipt references different package")
    if type(body["chunk_count"]) is not int or body["chunk_count"] != len(manifest_body["chunks"]):
        raise StorageError("receipt chunk count mismatch")
    if not isinstance(body["received_at"], str):
        raise StorageError("invalid receipt timestamp")
    try:
        parsed = datetime.fromisoformat(body["received_at"])
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("naive timestamp")
    except ValueError as exc:
        raise StorageError("invalid receipt timestamp") from exc
    return body


def decrypt_package(package: dict[str, Any], store: str | Path, output: str | Path,
                    content_key: bytes, trusted_artist: bytes) -> Path:
    """Reconstruct original file offline from any full replica and a content key."""
    if not isinstance(content_key, bytes) or len(content_key) != 32:
        raise StorageError("expected 32-byte content key")
    body = verify_package(package, store, trusted_artist)
    aes = AESGCM(content_key)
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".decrypt-", delete=False) as f:
            temp = f.name
            for chunk in body["chunks"]:
                ciphertext = _read_verified_chunk(store, chunk)
                try:
                    plain = aes.decrypt(from_b64(chunk["nonce"], 12), ciphertext, _aad(body["file_id"], chunk["index"]))
                except InvalidTag as exc:
                    raise StorageError("decryption failed: wrong key or tampered data") from exc
                if len(plain) != chunk["plain_bytes"]:
                    raise StorageError("decrypted chunk length mismatch")
                f.write(plain)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, destination)
        temp = None
    finally:
        if temp:
            Path(temp).unlink(missing_ok=True)
    return destination
