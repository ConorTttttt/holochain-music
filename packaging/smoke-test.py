#!/usr/bin/env python3
"""Black-box smoke test of an INSTALLED holochain-music (no repo imports).

    python3 smoke-test.py [/usr/bin/holochain-music] [--keep]

Starts an artist and a listener instance with throw-away homes and an
isolated loopback bootstrap, then via the HTTP API only: publish a generated
tone, discover it, request a licence privately, grant it, stream it, and
finally restart the listener with --offline and play the downloaded copy.
Uses the silent `null` audio backend. Same machine; not a two-computer test.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import wave

WINDOWS = sys.platform == "win32"
DEFAULT_LAUNCHER = (r"C:\Program Files\Holochain Music\holochain-music.exe" if WINDOWS
                    else "/usr/bin/holochain-music")
LAUNCHER = next((a for a in sys.argv[1:] if not a.startswith("--")), DEFAULT_LAUNCHER)
KEEP = "--keep" in sys.argv


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Instance:
    def __init__(self, name: str, base: Path, bootstrap: str):
        self.name, self.home = name, base / name
        self.home.mkdir(parents=True)
        (self.home / "config").mkdir()
        (self.home / "config" / "settings.json").write_text(json.dumps({
            "bootstrap_url": bootstrap, "relay_url": bootstrap, "audio_backend": "null",
            "host_max_rate": 512 * 1024}))
        self.proc = None

    def start(self, *extra: str) -> None:
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.home), "HOLOCHAIN_MUSIC_HOME": str(self.home),
               "LANG": "C.UTF-8"}
        if WINDOWS:  # clean env too, but Windows processes need SystemRoot/TEMP
            root = os.environ.get("SystemRoot", r"C:\Windows")
            env = {"SystemRoot": root, "PATH": rf"{root}\System32;{root}", "TEMP": str(self.home),
                   "TMP": str(self.home), "USERPROFILE": str(self.home), "LOCALAPPDATA": str(self.home),
                   "HOLOCHAIN_MUSIC_HOME": str(self.home)}
        self.log = open(self.home / "launcher.log", "w")
        self.proc = subprocess.Popen([LAUNCHER, "start", "--no-browser", "--audio", "null", *extra],
                                     stdout=subprocess.PIPE, stderr=self.log, text=True, env=env)
        for line in self.proc.stdout:
            m = re.search(r"(http://127\.0\.0\.1:\d+)/#token=(\S+)", line)
            if m:
                self.base, self.token = m.group(1), m.group(2)
                return
        raise SystemExit(f"{self.name}: launcher exited; see {self.home / 'launcher.log'}")

    def api(self, path: str, body=None):
        req = urllib.request.Request(self.base + path, method="GET" if body is None else "POST",
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"Authorization": f"Bearer {self.token}", "Origin": self.base,
                                              "Content-Type": "application/json"})
        try:
            return json.loads(urllib.request.urlopen(req, timeout=180).read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"{self.name} {path}: {json.loads(exc.read()).get('error')}") from None

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            if WINDOWS:  # no SIGTERM: ask the app to shut down over its own API
                try:
                    self.api("/api/shutdown", {})
                except Exception:
                    self.proc.kill()
            else:
                self.proc.send_signal(signal.SIGTERM)
            self.proc.wait(timeout=60)
        self.proc = None


def wait(what: str, fn, timeout: float = 420, interval: float = 3):
    deadline, last = time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except Exception as exc:
            last = exc
        time.sleep(interval)
    raise SystemExit(f"FAIL: timed out waiting for {what}: {last}")


def play_to_end(inst: Instance, file_id: str) -> dict:
    inst.api("/api/play", {"file_id": file_id})
    return wait("playback", lambda: (s := inst.api("/api/state")["player"])["state"] in ("finished", "error") and s,
                timeout=180, interval=0.5)


def main() -> int:
    base = Path(tempfile.mkdtemp(prefix="hm-smoke-", dir=os.environ.get("TMPDIR") or (None if WINDOWS else "/tmp")))
    bootstrap = f"http://127.0.0.1:{free_port()}"
    artist, listener = Instance("artist", base, bootstrap), Instance("listener", base, bootstrap)
    t0 = time.monotonic()
    try:
        artist.start()
        listener.start()
        for inst in (artist, listener):
            state = inst.api("/api/state")
            assert state["online"], f"{inst.name} offline: {state['status']}"
        print("ok  both instances online", flush=True)
        wav = base / "tone.wav"
        with wave.open(str(wav), "wb") as w:
            w.setnchannels(2); w.setsampwidth(2); w.setframerate(44100)
            w.writeframes(b"".join(struct.pack("<hh", s, s) for s in
                                   (int(6000 * math.sin(2 * math.pi * 330 * i / 44100)) for i in range(44100 * 10))))
        artist.api("/api/artist/profile", {"display_name": "Smoke Artist", "biography": "generated"})
        published = artist.api("/api/artist/publish", {"path": str(wav), "title": "Smoke Tone"})
        fid = published["file_id"]
        agent = artist.api("/api/state")["agent"]
        key = f"{agent}:{published['track_id']}"
        print("ok  artist published", fid[:12], flush=True)
        wait("discovery", lambda: any(t["key"] == key for t in listener.api("/api/catalogue/browse", {})["tracks"]))
        print(f"ok  listener discovered track ({time.monotonic() - t0:.0f}s)", flush=True)
        try:
            listener.api("/api/play", {"file_id": fid})
            raise SystemExit("FAIL: played without a grant")
        except RuntimeError:
            print("ok  playback refused without a grant", flush=True)
        wait("private request", lambda: listener.api("/api/access/request",
                                                    {"track_key": key, "kind": "perpetual-personal"}), 180)
        req = wait("request in artist inbox", lambda: [r for r in artist.api("/api/artist/requests", {})["requests"]
                                                       if r["file_id"] == fid], 120)
        wait("grant delivery", lambda: artist.api("/api/artist/grant", {"request_hash": req[0]["request_hash"],
                                                                       "kind": "perpetual-personal"}), 120)
        wait("grant import", lambda: listener.api("/api/grants/sync", {})["new_grants"] or
             any(t["file_id"] == fid and t["playable"] for t in listener.api("/api/library")["tracks"]), 120)
        print("ok  private licence received", flush=True)
        s = play_to_end(listener, fid)
        assert s["state"] == "finished" and s["source"] == "streaming", s
        print(f"ok  streamed to the end (first audio {s['time_to_first_audio_ms']} ms)", flush=True)
        wait("download", lambda: any(t["file_id"] == fid and t["offline_ready"]
                                     for t in listener.api("/api/library")["tracks"]), 180, 1)
        print("ok  download complete, offline ready", flush=True)
        artist.stop()
        listener.stop()
        listener.start("--offline")
        assert not listener.api("/api/state")["online"]
        s = play_to_end(listener, fid)
        assert (s["state"], s["source"]) == ("finished", "offline"), s
        print("ok  offline playback with no network services started", flush=True)
        print(f"PASS in {time.monotonic() - t0:.0f}s")
        return 0
    finally:
        artist.stop()
        listener.stop()
        if KEEP:
            print("kept", base)
        else:
            shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
