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
    def __init__(self, admin_port: int, *, app_id: str, log_path: Path,
                 pins: dict | None = None, timeout: float = 60):
        self.admin_port, self.app_id, self.log_path = admin_port, app_id, Path(log_path)
        self.pins = pins or {}
        self.timeout = timeout
        self.proc: subprocess.Popen | None = None
        self.whoami: dict | None = None
        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self._buffer = bytearray()

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
        return self.whoami

    def _read_line(self, timeout: float) -> dict:
        assert self.proc and self.proc.stdout
        deadline = time.monotonic() + timeout
        while b"\n" not in self._buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BridgeError("conductor bridge timed out")
            readable, _, _ = select.select([self.proc.stdout], [], [], remaining)
            if not readable:
                continue
            data = os.read(self.proc.stdout.fileno(), 65536)
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

    def call(self, op: str, **args):
        with self._lock:
            if self.proc is None or self.proc.poll() is not None:
                raise BridgeError("conductor bridge is not running")
            request_id = next(self._ids)
            line = json.dumps({"id": request_id, "op": op, "args": args}, separators=(",", ":")) + "\n"
            try:
                assert self.proc.stdin
                self.proc.stdin.write(line.encode())
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise BridgeError("conductor bridge is not running") from exc
            reply = self._read_line(self.timeout)
            if reply.get("id") != request_id:
                raise BridgeError("conductor bridge reply out of sequence")
            if not reply.get("ok"):
                raise BridgeError(str(reply.get("error", "conductor call failed"))[:300])
            return reply.get("result")

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
