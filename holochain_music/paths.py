"""Per-user data, config and state locations, never the source tree.

Linux: XDG. Windows: %LOCALAPPDATA%\\HolochainMusic (see holochain_storage.portable)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from holochain_storage import portable

APP = "holochain-music"
APP_WINDOWS = "HolochainMusic"
# Lair's in-process keystore listens on a unix socket inside the conductor
# directory; Linux limits socket paths to 108 bytes. (Windows lair uses a
# named pipe, so the limit does not apply there.)
MAX_SOCKET_PATH = 100


class PathError(RuntimeError):
    pass


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
        data, config = portable.user_data_root(APP, APP_WINDOWS)
        return cls(data=data, config=config)

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
    @property
    def session_file(self) -> Path: return self.data / "session.json"

    def ensure(self) -> None:
        for path in (self.data, self.config, self.keys, self.conductor, self.library, self.host, self.logs):
            path.mkdir(parents=True, exist_ok=True)
            try:
                portable.make_private_dir(path)
            except portable.PortabilityError as exc:
                raise PathError(str(exc)) from exc
        if portable.IS_WINDOWS:
            return
        socket = self.conductor / "conductor" / "ks" / "socket"
        if len(str(socket)) > MAX_SOCKET_PATH:
            raise PathError(
                f"data directory path is too long for the Holochain keystore socket ({len(str(socket))} > "
                f"{MAX_SOCKET_PATH} bytes); set HOLOCHAIN_MUSIC_HOME to a shorter path")
