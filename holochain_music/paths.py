"""Per-user data, config and state locations (XDG), never the source tree."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

APP = "holochain-music"
# Lair's in-process keystore listens on a unix socket inside the conductor
# directory; Linux limits socket paths to 108 bytes.
MAX_SOCKET_PATH = 100


class PathError(RuntimeError):
    pass


def _xdg(name: str, fallback: str) -> Path:
    value = os.environ.get(name)
    return Path(value) if value and Path(value).is_absolute() else Path.home() / fallback


@dataclass(frozen=True)
class AppPaths:
    data: Path
    config: Path

    @classmethod
    def default(cls) -> "AppPaths":
        home = os.environ.get("HOLOCHAIN_MUSIC_HOME")
        if home:
            root = Path(home).expanduser().resolve()
            return cls(data=root / "data", config=root / "config")
        return cls(data=_xdg("XDG_DATA_HOME", ".local/share") / APP,
                   config=_xdg("XDG_CONFIG_HOME", ".config") / APP)

    # Private directories (0700): keys, conductor, library ciphertext.
    @property
    def keys(self) -> Path: return self.data / "keys"
    @property
    def conductor(self) -> Path: return self.data / "conductor"
    @property
    def library(self) -> Path: return self.data / "library"
    @property
    def host(self) -> Path: return self.data / "host"
    @property
    def logs(self) -> Path: return self.data / "logs"
    @property
    def settings_file(self) -> Path: return self.config / "settings.json"
    @property
    def lock_file(self) -> Path: return self.data / "app.lock"

    def ensure(self) -> None:
        for path in (self.data, self.config, self.keys, self.conductor, self.library, self.host, self.logs):
            path.mkdir(parents=True, exist_ok=True)
            if path.is_symlink():
                raise PathError(f"refusing symlinked application directory {path}")
            path.chmod(0o700)
        socket = self.conductor / "conductor" / "ks" / "socket"
        if len(str(socket)) > MAX_SOCKET_PATH:
            raise PathError(
                f"data directory path is too long for the Holochain keystore socket ({len(str(socket))} > "
                f"{MAX_SOCKET_PATH} bytes); set HOLOCHAIN_MUSIC_HOME to a shorter path")
