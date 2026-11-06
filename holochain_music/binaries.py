"""Locate the native executables the app supervises.

Search order per tool: explicit environment variable, the packaged
`libexec` directory (``$HOLOCHAIN_MUSIC_LIBEXEC``; else ``<root>/bin`` when
this package is installed as ``<root>/python/holochain_music`` — the layout
of both the .deb (``/usr/lib/holochain-music``) and the Windows installer
(``C:\\Program Files\\Holochain Music``); else the .deb default), then
``PATH``. Every result is absolute. Windows tools carry ``.exe``.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

from holochain_storage import portable

TOOLS = {
    "holochain": "HOLOCHAIN_BIN",
    "hc": "HC_BIN",
    "kitsune2-bootstrap-srv": "KITSUNE2_BOOTSTRAP_BIN",
    "music_app_bridge": "HOLOCHAIN_MUSIC_BRIDGE_BIN",
    "holochain-music-moq": "HOLOCHAIN_MOQ_BIN",
    "aplay": "APLAY_BIN",
}
LIBEXEC_DEFAULT = Path("/usr/lib/holochain-music/bin")


class MissingBinary(RuntimeError):
    pass


def installed_root() -> Path | None:
    """`<root>` if this package lives at `<root>/python/holochain_music`."""
    here = Path(__file__).resolve().parent
    if here.parent.name == "python" and (here.parent.parent / "bin").is_dir():
        return here.parent.parent
    return None


def libexec_dirs() -> list[Path]:
    dirs = []
    if os.environ.get("HOLOCHAIN_MUSIC_LIBEXEC"):
        dirs.append(Path(os.environ["HOLOCHAIN_MUSIC_LIBEXEC"]))
    root = installed_root()
    if root is not None:
        dirs.append(root / "bin")
    if not portable.IS_WINDOWS:
        dirs.append(LIBEXEC_DEFAULT)
    return dirs


def find(tool: str, *, required: bool = True) -> Path | None:
    if tool not in TOOLS:
        raise KeyError(tool)
    override = os.environ.get(TOOLS[tool])
    candidates = [Path(override)] if override else []
    candidates += [d / portable.exe(tool) for d in libexec_dirs()]
    found = shutil.which(portable.exe(tool))
    if found:
        candidates.append(Path(found))
    for candidate in candidates:
        if candidate.is_absolute() and candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    if required:
        raise MissingBinary(f"{tool} not found (set {TOOLS[tool]} or install the package)")
    return None


def find_happ() -> Path:
    """The packaged hApp bundle the conductor installs on first run."""
    candidates = []
    if os.environ.get("HOLOCHAIN_MUSIC_HAPP"):
        candidates.append(Path(os.environ["HOLOCHAIN_MUSIC_HAPP"]))
    candidates += [d.parent / "holochain_music.happ" for d in libexec_dirs()]
    candidates.append(Path(__file__).resolve().parent.parent / "integration" / "workdir" / "holochain_music.happ")
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise MissingBinary("holochain_music.happ not found (set HOLOCHAIN_MUSIC_HAPP)")
