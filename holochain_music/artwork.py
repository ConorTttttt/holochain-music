"""Small, locally stored album artwork; no catalogue wire-format changes.

Phase 1 supports bounded RGB/RGBA PNGs only. It removes all ancillary
metadata (including text, EXIF and location-bearing chunks), validates PNG
chunk CRCs and the decoded scanlines, and never processes SVG/HTML or URLs.
Files stay on the artist's own device and are only served by the authenticated
loopback application. Peer-to-peer distribution is NOT implemented here.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import struct
import tempfile
import zlib

SIG = b"\x89PNG\r\n\x1a\n"
ALBUM_ID = re.compile(r"[0-9a-f]{32}\Z")
MAX_SOURCE_BYTES = 768 * 1024
MAX_OUTPUT_BYTES = 768 * 1024
MAX_DIMENSION = 1200


class ArtworkError(ValueError):
    pass


def _chunk(kind: bytes, data: bytes) -> bytes:
    return (struct.pack(">I", len(data)) + kind + data +
            struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))


def clean_png_bytes(source: bytes) -> bytes:
    """Validate and strip PNG metadata without external/native image libraries."""
    if not isinstance(source, bytes) or not SIG == source[:8] or len(source) > MAX_SOURCE_BYTES:
        raise ArtworkError("cover must be a PNG smaller than 768 KiB")
    position = len(SIG)
    ihdr = None
    compressed = bytearray()
    ended = False
    seen_idat = False
    while position < len(source):
        if position + 12 > len(source):
            raise ArtworkError("truncated PNG")
        length = struct.unpack_from(">I", source, position)[0]
        kind = source[position + 4:position + 8]
        end = position + 12 + length
        if length > MAX_SOURCE_BYTES or end > len(source):
            raise ArtworkError("invalid PNG chunk length")
        data = source[position + 8:position + 8 + length]
        crc = struct.unpack_from(">I", source, position + 8 + length)[0]
        if zlib.crc32(kind + data) & 0xFFFFFFFF != crc:
            raise ArtworkError("invalid PNG checksum")
        if kind == b"IHDR":
            if ihdr is not None or position != len(SIG) or length != 13:
                raise ArtworkError("invalid PNG header")
            width, height, depth, colour, compression, filtering, interlace = struct.unpack(">IIBBBBB", data)
            if (not 1 <= width <= MAX_DIMENSION or not 1 <= height <= MAX_DIMENSION
                    or depth != 8 or colour not in (2, 6)
                    or compression != 0 or filtering != 0 or interlace != 0):
                raise ArtworkError("cover must be non-interlaced 8-bit RGB/RGBA PNG, up to 1200px")
            ihdr = data
        elif kind == b"IDAT":
            if ihdr is None or ended:
                raise ArtworkError("invalid PNG data order")
            seen_idat = True
            compressed.extend(data)
            if len(compressed) > MAX_SOURCE_BYTES:
                raise ArtworkError("PNG compressed data too large")
        elif kind == b"IEND":
            if not seen_idat or length != 0 or end != len(source):
                raise ArtworkError("invalid PNG ending")
            ended = True
        elif kind in (b"PLTE", b"tRNS"):
            # Palettes/transparency metadata are unnecessary for RGB/RGBA input.
            # A colour-key transparency chunk would change the image if stripped,
            # so reject it rather than presenting incorrect cover artwork.
            if kind == b"tRNS":
                raise ArtworkError("convert transparent PNG to RGBA before importing")
        elif kind[0] & 32 == 0:
            raise ArtworkError("unsupported critical PNG chunk")
        # Ancillary chunks (EXIF, XMP, tEXt, iTXt, etc.) are intentionally discarded.
        position = end
        if ended:
            break
    if ihdr is None or not seen_idat or not ended:
        raise ArtworkError("incomplete PNG")
    width, height, _, colour, *_ = struct.unpack(">IIBBBBB", ihdr)
    stride = width * (3 if colour == 2 else 4)
    expected = height * (stride + 1)
    try:
        decoder = zlib.decompressobj()
        raw = decoder.decompress(bytes(compressed), expected + 1)
        if len(raw) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
            raise ArtworkError("invalid or oversized PNG pixels")
        if decoder.flush():
            raise ArtworkError("invalid compressed PNG data")
    except zlib.error as exc:
        raise ArtworkError("PNG image pixels cannot be decoded") from exc
    if any(raw[y * (stride + 1)] > 4 for y in range(height)):
        raise ArtworkError("invalid PNG scanline filter")
    result = SIG + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", bytes(compressed)) + _chunk(b"IEND", b"")
    if len(result) > MAX_OUTPUT_BYTES:
        raise ArtworkError("PNG cover exceeds the size limit")
    return result


def load_cover(path: Path) -> bytes:
    path = Path(path).expanduser()
    if (not path.is_absolute() or path.is_symlink() or
            path.suffix.lower() != ".png" or not path.is_file()):
        raise ArtworkError("choose an existing absolute .png path (not a symlink)")
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise ArtworkError("PNG cover is too large (maximum 768 KiB)")
    return clean_png_bytes(path.read_bytes())


class AlbumArtworkStore:
    def __init__(self, root: Path):
        self.root = Path(root)

    def _target(self, album_id: str) -> Path:
        if not isinstance(album_id, str) or not ALBUM_ID.fullmatch(album_id):
            raise ArtworkError("invalid album ID")
        return self.root / (album_id + ".png")

    def save(self, album_id: str, image: bytes) -> None:
        target = self._target(album_id)
        if image != clean_png_bytes(image):
            raise ArtworkError("cover has not been stripped of metadata")
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        fd, temporary = tempfile.mkstemp(prefix=".tmp-cover-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(image)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, target)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def read(self, album_id: str) -> bytes | None:
        target = self._target(album_id)
        if target.is_symlink() or not target.is_file():
            return None
        if target.stat().st_size > MAX_OUTPUT_BYTES:
            return None
        try:
            data = target.read_bytes()
            return data if data == clean_png_bytes(data) else None
        except (ArtworkError, OSError):
            return None

    def has(self, album_id: str) -> bool:
        return self.read(album_id) is not None

    def delete(self, album_id: str) -> None:
        self._target(album_id).unlink(missing_ok=True)
