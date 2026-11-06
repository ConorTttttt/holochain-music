"""JSON-lines client for the long-running `music_app_bridge` process.

Records returned here carry the action author *as reported by this
machine's validating conductor*. That is the S2/S5 trust anchor; every other
claim (signatures, digests, grants) is still verified by the caller.
"""
from __future__ import annotations

import itertools
import json
import os
import select
import subprocess
import threading
import time
from pathlib import Path

from holochain_storage.holochain_identity import AuthoredRecord

from . import binaries

MAX_REPLY_BYTES = 4 * 1024 * 1024


class BridgeError(RuntimeError):
    pass


class Bridge:
    """Concurrent client: one reader thread routes replies by request id, so a
    slow call (e.g. call_remote to an offline peer) never blocks other calls."""

    def __init__(self, admin_port: int, *, app_id: str, log_path: Path,
                 pins: dict | None = None, timeout: float = 90):
        self.admin_port, self.app_id, self.log_path = admin_port, app_id, Path(log_path)
        self.pins = pins or {}
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self.whoami: dict | None = None
        self._write_lock = threading.Lock()
        self._pending: dict[int, list] = {}
        self._pending_lock = threading.Lock()
        self._ids = itertools.count(1)
        self._buffer = bytearray()
        self._dead: str | None = None

    def start(self) -> dict:
        argv = [str(binaries.find("music_app_bridge")), "--admin", f"127.0.0.1:{self.admin_port}",
                "--app-id", self.app_id]
        if self.pins.get("catalogue_dna"):
            argv += ["--expect-catalogue-dna", self.pins["catalogue_dna"]]
        if self.pins.get("storage_dna"):
            argv += ["--expect-storage-dna", self.pins["storage_dna"]]
        log = open(self.log_path, "ab")
        try:
            self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=log, bufsize=0)
        finally:
            log.close()
        ready = self._read_line(self.timeout)
        if not ready.get("ready"):
            raise BridgeError("conductor bridge did not start")
        self.whoami = ready["whoami"]
        threading.Thread(target=self._reader, name="hm-bridge-reader", daemon=True).start()
        return self.whoami

    def _read_line(self, timeout: float, proc: subprocess.Popen | None = None) -> dict:
        proc = proc or self.proc
        if proc is None or proc.stdout is None:
            raise BridgeError("conductor bridge is not running")
        deadline = time.monotonic() + timeout
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BridgeError("conductor bridge timed out")
            try:
                readable, _, _ = select.select([proc.stdout], [], [], remaining)
            except (ValueError, OSError) as exc:  # stdout closed by stop()
                raise BridgeError("conductor bridge exited") from exc
            if not readable:
                continue
            try:
                data = os.read(proc.stdout.fileno(), 65536)
            except (ValueError, OSError) as exc:
                raise BridgeError("conductor bridge exited") from exc
            if not data:
                raise BridgeError("conductor bridge exited (see bridge log)")
            self._buffer.extend(data)
            if len(self._buffer) > MAX_REPLY_BYTES:
                raise BridgeError("oversized conductor reply")
        line, _, rest = self._buffer.partition(b"\n")
        self._buffer = bytearray(rest)
        try:
            value = json.loads(line)
        except ValueError as exc:
            raise BridgeError("invalid conductor reply") from exc
        if not isinstance(value, dict):
            raise BridgeError("invalid conductor reply")
        return value

    def _reader(self) -> None:
        reason = "conductor bridge exited (see bridge log)"
        proc = self.proc  # stop() clears self.proc; keep our own handle
        try:
            while proc.poll() is None:
                try:
                    reply = self._read_line(3600, proc)
                except BridgeError as exc:
                    if "timed out" in str(exc):
                        continue
                    reason = str(exc)
                    break
                with self._pending_lock:
                    slot = self._pending.get(reply.get("id"))
                if slot is not None:
                    slot[1] = reply
                    slot[0].set()
        finally:
            self._dead = reason
            with self._pending_lock:
                for slot in self._pending.values():
                    slot[0].set()

    def call(self, op: str, timeout: float | None = None, **args):
        if self.proc is None or self.proc.poll() is not None or self._dead:
            raise BridgeError("conductor bridge is not running")
        request_id = next(self._ids)
        slot = [threading.Event(), None]
        with self._pending_lock:
            self._pending[request_id] = slot
        try:
            line = json.dumps({"id": request_id, "op": op, "args": args}, separators=(",", ":")) + "\n"
            with self._write_lock:
                try:
                    assert self.proc.stdin
                    self.proc.stdin.write(line.encode())
                    self.proc.stdin.flush()
                except (BrokenPipeError, OSError) as exc:
                    raise BridgeError("conductor bridge is not running") from exc
            if not slot[0].wait(timeout or self.timeout):
                raise BridgeError("conductor call timed out")
            reply = slot[1]
            if reply is None:
                raise BridgeError(self._dead or "conductor bridge is not running")
            if not reply.get("ok"):
                raise BridgeError(str(reply.get("error", "conductor call failed"))[:300])
            return reply.get("result")
        finally:
            with self._pending_lock:
                self._pending.pop(request_id, None)

    def records(self, op: str, **args) -> list[AuthoredRecord]:
        rows = self.call(op, **args)
        if not isinstance(rows, list):
            raise BridgeError("expected a list of records")
        return [to_record(r) for r in rows]

    def record(self, op: str, **args) -> AuthoredRecord | None:
        row = self.call(op, **args)
        return None if row is None else to_record(row)

    def stop(self) -> None:
        proc, self.proc = self.proc, None
        if proc is not None and proc.poll() is None:
            try:
                assert proc.stdin
                proc.stdin.close()
                proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                proc.kill()


def to_record(row) -> AuthoredRecord:
    if (not isinstance(row, dict) or set(row) != {"author", "action_hash", "body"}
            or not isinstance(row["author"], str) or not row["author"]
            or not isinstance(row["action_hash"], str) or not isinstance(row["body"], dict)):
        raise BridgeError("malformed conductor record")
    return AuthoredRecord(author=row["author"], action_hash=row["action_hash"], body=row["body"])
