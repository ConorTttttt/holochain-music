"""Artist-signed, publicly decryptable album art over the EXISTING S1/MoQ host.

This is deliberately NOT an audio licence or a confidential storage key.
Art is public. A domain-separated, deterministic key wraps it in the S1
AES-GCM package only to reuse MoQ's signed-manifest/chunk verification. Anyone
who knows the artist's Holochain agent and album ID can derive this key.

New v1 album records can pin the signed manifest at publication time.
Existing v1 albums cannot be amended by simply republishing their album ID.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from holochain_storage.package import (
    CHUNK_BYTES, SCHEMA as PACKAGE_SCHEMA, StorageError,
    _aad, _assert_manifest, _read_verified_chunk, _sign, _store_chunk, _verify_signed,
    b64, canonical, from_b64, manifest_digest, public_key_bytes, sha256,
)
from .artwork import ALBUM_ID, MAX_OUTPUT_BYTES, ArtworkError, AlbumArtworkStore, clean_png_bytes
from .library import _atomic_json

# Only a URL-safe agent identifier from the authenticated Holochain conductor.
AGENT = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
PUBLIC_ID_DOMAIN = b"holochain-music/public-artwork-file/v1\x00"
PUBLIC_KEY_DOMAIN = b"holochain-music/public-artwork-key/v1\x00"
MAX_ART_CHUNKS = 4
MAX_CACHE_RECORD = 64 * 1024


def _identity(artist_agent: str, album_id: str) -> bytes:
    if not isinstance(artist_agent, str) or not AGENT.fullmatch(artist_agent):
        raise ArtworkError("invalid artwork artist agent")
    if not isinstance(album_id, str) or not ALBUM_ID.fullmatch(album_id):
        raise ArtworkError("invalid artwork album ID")
    return artist_agent.encode("ascii") + b"\x00" + bytes.fromhex(album_id)


def public_artwork_file_id(artist_agent: str, album_id: str) -> str:
    return sha256(PUBLIC_ID_DOMAIN + _identity(artist_agent, album_id))


def public_artwork_key(artist_agent: str, album_id: str) -> bytes:
    """Intentionally public. Never use as an audio content-encryption key."""
    return hashlib.sha256(PUBLIC_KEY_DOMAIN + _identity(artist_agent, album_id)).digest()


def publish_public_artwork(image: bytes, *, artist_agent: str, album_id: str, signer, store: Path) -> dict:
    """Pack an already scrubbed PNG in S1 format for the existing MoQ host."""
    if not isinstance(image, bytes) or not image or image != clean_png_bytes(image):
        raise ArtworkError("cover must be a clean canonical PNG")
    file_id = public_artwork_file_id(artist_agent, album_id)
    key = public_artwork_key(artist_agent, album_id)
    chunks = []
    aes = AESGCM(key)
    for offset in range(0, len(image), CHUNK_BYTES):
        index = len(chunks)
        data = image[offset:offset + CHUNK_BYTES]
        nonce = os.urandom(12)
        ciphertext = aes.encrypt(nonce, data, _aad(file_id, index))
        chunks.append({"index": index, "sha256": _store_chunk(Path(store), ciphertext),
                       "nonce": b64(nonce), "plain_bytes": len(data),
                       "cipher_bytes": len(ciphertext)})
    body = {"schema": PACKAGE_SCHEMA, "file_id": file_id, "cipher": "AES-256-GCM",
            "chunk_size": CHUNK_BYTES, "total_plain_bytes": len(image), "chunks": chunks}
    _assert_manifest(body)
    if not 1 <= len(chunks) <= MAX_ART_CHUNKS:
        raise ArtworkError("too many artwork chunks")
    return _sign(body, signer)


def verify_public_artwork_manifest(manifest: dict, *, artist_agent: str, album_id: str,
                                   trusted_artist: bytes, expected_digest: str) -> dict:
    """Verify both Holochain album pin and artist S2 signing key binding."""
    _identity(artist_agent, album_id)
    if not isinstance(expected_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_digest):
        raise ArtworkError("invalid artwork manifest commitment")
    if manifest_digest(manifest) != expected_digest:
        raise ArtworkError("artwork manifest differs from album catalogue pin")
    body = _verify_signed(manifest, trusted_artist, "artwork manifest")
    _assert_manifest(body)
    if (body["file_id"] != public_artwork_file_id(artist_agent, album_id)
            or not 1 <= body["total_plain_bytes"] <= MAX_OUTPUT_BYTES
            or not 1 <= len(body["chunks"]) <= MAX_ART_CHUNKS):
        raise ArtworkError("artwork manifest does not match the album or size limit")
    return body


def recover_public_artwork(manifest: dict, *, store: Path, artist_agent: str,
                           album_id: str, trusted_artist: bytes, expected_digest: str) -> bytes:
    """Decrypt PUBLIC S1 artwork only after verifying artist and album pins."""
    body = verify_public_artwork_manifest(
        manifest, artist_agent=artist_agent, album_id=album_id,
        trusted_artist=trusted_artist, expected_digest=expected_digest)
    aes = AESGCM(public_artwork_key(artist_agent, album_id))
    output = bytearray()
    for chunk in body["chunks"]:
        ciphertext = _read_verified_chunk(store, chunk)
        try:
            plain = aes.decrypt(from_b64(chunk["nonce"], 12), ciphertext,
                                _aad(body["file_id"], chunk["index"]))
        except InvalidTag as exc:
            raise ArtworkError("artwork chunk authentication failed") from exc
        if len(plain) != chunk["plain_bytes"]:
            raise ArtworkError("artwork chunk length mismatch")
        output.extend(plain)
        if len(output) > MAX_OUTPUT_BYTES:
            raise ArtworkError("artwork exceeds size limit")
    image = bytes(output)
    if len(image) != body["total_plain_bytes"] or image != clean_png_bytes(image):
        raise ArtworkError("received artwork is not a canonical PNG")
    return image


class VerifiedArtworkCache:
    """Artist-separated, offline-readable cache of Holochain-pinned artwork.

    The signer must be resolved via authenticated conductor bindings BEFORE
    calling save(). Offline, the stored verified pin/signer/chunk commitment
    is rechecked against the saved bytes. Cache does not mint new trust.
    """

    def __init__(self, root: Path):
        self.root = Path(root)

    def _directory(self, artist_agent: str, album_id: str) -> Path:
        _identity(artist_agent, album_id)
        digest = sha256(artist_agent.encode("ascii"))
        return self.root / digest

    def save(self, *, artist_agent: str, album_id: str, manifest: dict,
             trusted_artist: bytes, expected_digest: str, image: bytes) -> None:
        verify_public_artwork_manifest(
            manifest, artist_agent=artist_agent, album_id=album_id,
            trusted_artist=trusted_artist, expected_digest=expected_digest)
        if not isinstance(image, bytes) or image != clean_png_bytes(image):
            raise ArtworkError("refusing unverified or noncanonical artwork")
        directory = self._directory(artist_agent, album_id)
        AlbumArtworkStore(directory).save(album_id, image)
        record = {"artist_agent": artist_agent, "album_id": album_id, "manifest": manifest,
                  "manifest_sha256": expected_digest, "artist_key_hex": trusted_artist.hex(),
                  "image_sha256": sha256(image)}
        _atomic_json(directory / (album_id + ".json"), record)

    def read(self, artist_agent: str, album_id: str) -> bytes | None:
        directory = self._directory(artist_agent, album_id)
        record_path = directory / (album_id + ".json")
        if record_path.is_symlink() or not record_path.is_file():
            return None
        try:
            if record_path.stat().st_size > MAX_CACHE_RECORD:
                return None
            record = json.loads(record_path.read_text(encoding="utf-8"))
            if (record.get("artist_agent") != artist_agent or record.get("album_id") != album_id
                    or not isinstance(record.get("artist_key_hex"), str)):
                return None
            key = bytes.fromhex(record["artist_key_hex"])
            verify_public_artwork_manifest(
                record["manifest"], artist_agent=artist_agent, album_id=album_id,
                trusted_artist=key, expected_digest=record["manifest_sha256"])
            image = AlbumArtworkStore(directory).read(album_id)
            if image is None or sha256(image) != record["image_sha256"]:
                return None
            return image
        except (OSError, ValueError, TypeError, KeyError, StorageError, ArtworkError):
            return None
