"""Bounded, public catalogue decorations (never audio or licence data)."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re

ARTWORK_SCHEMA = "holochain-music/artwork/v1"
MAX_ARTWORK_BYTES = 32 * 1024
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def genres_list(values) -> list[str]:
    if not isinstance(values, list) or len(values) > 6:
        raise ValueError("provide up to six genres")
    seen = set()
    out = []
    for v in values:
        if (not isinstance(v, str) or not v or v != v.strip()
                or len(v.encode("utf-8")) > 32 or any(ord(c) < 32 or ord(c) == 127 for c in v)
                or v.casefold() in seen):
            raise ValueError("invalid or repeated genre")
        seen.add(v.casefold())
        out.append(v)
    return out


def artwork_bytes(*, mime_type: str, data_base64: str) -> bytes:
    if mime_type not in ("image/webp", "image/png", "image/jpeg"):
        raise ValueError("artwork must be WebP, PNG or JPEG")
    if not isinstance(data_base64, str) or len(data_base64) > ((MAX_ARTWORK_BYTES + 2) // 3) * 4:
        raise ValueError("artwork is too large")
    try:
        data = base64.b64decode(data_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid artwork encoding") from exc
    if not 0 < len(data) <= MAX_ARTWORK_BYTES:
        raise ValueError("artwork must be 1–32768 bytes")
    if not ((mime_type == "image/png" and data.startswith(b"\x89PNG\r\n\x1a\n"))
            or (mime_type == "image/jpeg" and data.startswith(b"\xff\xd8\xff"))
            or (mime_type == "image/webp" and len(data) >= 12
                and data[:4] == b"RIFF" and data[8:12] == b"WEBP")):
        raise ValueError("artwork content does not match declared format")
    return data


def validate_artwork_record(record: dict, *, author: str, digest: str) -> bytes:
    if (not isinstance(record, dict) or set(record) != {
            "schema", "artist_agent", "mime_type", "sha256", "data_base64"}
            or record.get("schema") != ARTWORK_SCHEMA or record.get("artist_agent") != author
            or not isinstance(digest, str) or not HEX64.fullmatch(digest)
            or record.get("sha256") != digest):
        raise ValueError("artwork not attributable to expected artist and hash")
    data = artwork_bytes(mime_type=record["mime_type"], data_base64=record["data_base64"])
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("artwork SHA-256 mismatch")
    return data
