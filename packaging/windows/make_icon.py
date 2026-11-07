"""Render holochain_music/ui/icon.svg's shapes to a Windows .ico (stdlib only).

The SVG is five primitives (rounded square, ring, dot, stem, note head), so
it is rasterised here directly with 4x4 supersampling instead of adding an
SVG renderer to the build. Output is deterministic: PNG-compressed ICO
entries at 16, 24, 32, 48, 64 and 256 px (Windows Vista and later).

    python3 make_icon.py OUT.ico
"""
from __future__ import annotations

import math
import struct
import sys
import zlib

BG, TEAL, WHITE = (0x1D, 0x2B, 0x3A), (0x5F, 0xD3, 0xA6), (0xE8, 0xF0, 0xF7)


def shade(x: float, y: float):
    """Colour at SVG coordinate (x, y) in the 64x64 viewBox, or None."""
    # rect 64x64 rx=14
    r = 14
    cx, cy = min(max(x, r), 64 - r), min(max(y, r), 64 - r)
    if (x - cx) ** 2 + (y - cy) ** 2 > r * r or not (0 <= x <= 64 and 0 <= y <= 64):
        return None
    colour = BG
    d = math.hypot(x - 32, y - 32)
    if 17 <= d <= 21:            # ring r=19, stroke 4
        colour = TEAL
    if d <= 6:                   # centre dot
        colour = TEAL
    # stem: line (44,14)-(44,36), width 4, round caps
    sy = min(max(y, 14), 36)
    if math.hypot(x - 44, y - sy) <= 2:
        colour = WHITE
    if math.hypot(x - 40, y - 38) <= 5:  # note head
        colour = WHITE
    return colour


def render(size: int) -> bytes:
    ss = 4
    rows = []
    for py in range(size):
        row = bytearray([0])  # PNG filter type 0
        for px in range(size):
            acc = [0, 0, 0, 0]
            for sy in range(ss):
                for sx in range(ss):
                    x = (px + (sx + 0.5) / ss) * 64 / size
                    y = (py + (sy + 0.5) / ss) * 64 / size
                    c = shade(x, y)
                    if c is not None:
                        acc[0] += c[0]; acc[1] += c[1]; acc[2] += c[2]; acc[3] += 255
            n = ss * ss
            alpha = acc[3] // n
            if alpha:
                cov = acc[3] // 255
                row += bytes((acc[0] // cov, acc[1] // cov, acc[2] // cov, alpha))
            else:
                row += b"\0\0\0\0"
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def ico(sizes=(16, 24, 32, 48, 64, 256)) -> bytes:
    images = [render(s) for s in sizes]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for s, img in zip(sizes, images):
        entries += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(img), offset)
        offset += len(img)
        blobs += img
    return header + entries + blobs


if __name__ == "__main__":
    with open(sys.argv[1], "wb") as f:
        f.write(ico())
