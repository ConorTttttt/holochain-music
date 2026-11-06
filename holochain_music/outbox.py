"""Store-and-retry delivery for private requests and grants.

Remote calls need both peers online. When the recipient is unreachable (or
asks us to retry), the *already signed* message is kept here and retried in
the background. Entries hold only what was about to be sent: public metadata,
the listener's X25519 *public* key, or a grant wrapped to the listener — never
a content key or private key. Rate-limit refusals are not retried.
"""
from __future__ import annotations

import secrets
import threading
import time
from pathlib import Path
from typing import Callable

from .bridge import BridgeError
from .library import _atomic_json, _read_json

RETRY_SECONDS = 30
EXPIRY_SECONDS = 7 * 24 * 3600
MAX_ITEMS = 200
RETRYABLE = ("unreachable", "busy", "timed out", "NetworkError", "not running")
OPS = ("send_access_request", "send_grant")


class OutboxError(RuntimeError):
    pass


def retryable(error: Exception) -> bool:
    return isinstance(error, BridgeError) and any(word in str(error) for word in RETRYABLE)


class Outbox:
    def __init__(self, path: Path, send: Callable[..., object], *, clock=time.time):
        self.path, self.send, self.clock = Path(path), send, clock
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def items(self) -> list[dict]:
        return _read_json(self.path, 4 * 1024 * 1024) if self.path.is_file() else []

    def _save(self, items: list[dict]) -> None:
        _atomic_json(self.path, items)

    def deliver(self, op: str, **args) -> dict:
        """Send now; queue on a retryable failure. Returns {"delivered"| "queued": True}."""
        if op not in OPS:
            raise OutboxError("unsupported delivery")
        try:
            self.send(op, **args)
            return {"delivered": True}
        except Exception as exc:
            if not retryable(exc):
                raise
            with self._lock:
                items = self.items()
                if len(items) >= MAX_ITEMS:
                    raise OutboxError("too many undelivered messages; try again later") from exc
                items.append({"id": secrets.token_hex(8), "op": op, "args": args, "created_at": int(self.clock()),
                              "attempts": 1, "last_error": str(exc)[:200]})
                self._save(items)
            return {"queued": True, "reason": str(exc)[:200]}

    def flush(self) -> dict:
        """One retry pass. Returns counts; never raises for per-item failures."""
        delivered = expired = 0
        with self._lock:
            keep = []
            for item in self.items():
                if self.clock() - item["created_at"] > EXPIRY_SECONDS:
                    expired += 1
                    continue
                try:
                    self.send(item["op"], **item["args"])
                    delivered += 1
                except Exception as exc:
                    if not retryable(exc):
                        continue  # permanent failure: drop (e.g. rate limited, invalid)
                    item["attempts"] += 1
                    item["last_error"] = str(exc)[:200]
                    keep.append(item)
            self._save(keep)
        return {"delivered": delivered, "expired": expired, "pending": len(keep)}

    def start(self, interval: float = RETRY_SECONDS) -> None:
        def run():
            while not self._stop.wait(interval):
                try:
                    self.flush()
                except Exception:
                    pass
        self._thread = threading.Thread(target=run, name="hm-outbox", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
