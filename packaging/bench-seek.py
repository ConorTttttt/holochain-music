#!/usr/bin/env python3
"""Seek-latency benchmark for an offline licensed WAV (5:31, 44.1 kHz stereo).

    PYTHONPATH=. python packaging/bench-seek.py [--seconds 331] [--seeks 20] [--device null] [--json OUT]

Uses the real application path (MusicApp offline -> Player -> S11 player ->
`aplay -D <device>`). Latency = time from the seek call to the first PCM
block for the new position being written to the output process. Also
samples the reported position every 50 ms to find stalls and backward jumps.
Works on old and new Player implementations (no API assumptions beyond
play/seek/status).
"""
from __future__ import annotations

import argparse
import json
import random
import statistics
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from holochain_storage.package import create_package, manifest_digest, public_key_bytes
from music_catalogue.content_grants import issue_personal_licence
from holochain_music import player as player_mod
from holochain_music.app import MusicApp
from holochain_music.paths import AppPaths

RATE, CH = 44100, 2
WRITES: list[tuple[float, int, int]] = []  # (time, output-instance id, bytes)
_lock = threading.Lock()


def make_wav(path: Path, seconds: int) -> None:
    import math
    one = b"".join(struct.pack("<hh", int(6000 * math.sin(2 * math.pi * 440 * i / RATE)),
                               int(6000 * math.sin(2 * math.pi * 660 * i / RATE))) for i in range(RATE))
    data_len = len(one) * seconds
    with path.open("wb") as f:
        f.write(struct.pack("<4sI4s4sIHHIIHH4sI", b"RIFF", 36 + data_len, b"WAVE", b"fmt ", 16, 1, CH, RATE,
                            RATE * CH * 2, CH * 2, 16, b"data", data_len))
        for _ in range(seconds):
            f.write(one)


def instrument(device: str) -> None:
    real = player_mod.AlsaOutput

    class Timed:
        n = 0

        def __init__(self, fmt, device="default", **kw):
            Timed.n += 1
            self.id = Timed.n
            self.inner = real(fmt, device=device, **kw)

        def write(self, data):
            self.inner.write(data)
            with _lock:
                WRITES.append((time.perf_counter(), self.id, len(data)))

        def close(self):
            self.inner.close()

        def abort(self):
            self.inner.abort()
    player_mod.AlsaOutput = Timed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=331)
    ap.add_argument("--seeks", type=int, default=20)
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--device", default="null")
    ap.add_argument("--json")
    ap.add_argument("--writes-only", action="store_true",
                    help="ignore Player.seek_metrics; time writes into new output processes (baseline method)")
    args = ap.parse_args()
    instrument(args.device)
    root = Path(tempfile.mkdtemp(prefix="hm-bench-", dir="/mnt/holochain/tmp"))
    app = MusicApp(AppPaths(data=root / "data", config=root / "config"))
    app.save_settings(audio_backend="alsa", audio_device=args.device)
    app.player.backend, app.player.device = "alsa", args.device
    app.start(offline=True)
    # Licensed track, already fully downloaded (encrypted) into the library CAS.
    wav = root / "track.wav"
    make_wav(wav, args.seconds)
    artist = Ed25519PrivateKey.generate()
    manifest, key = create_package(wav, app.library.cas, artist)
    wav.unlink()
    fid = manifest["body"]["file_id"]
    owner, listener = "uhCAkBenchArtist", "uhCAkBenchListener"
    app.library.add(manifest=manifest, meta={
        "manifest_sha256": manifest_digest(manifest), "artist_key_hex": public_key_bytes(artist).hex(),
        "artist_agent": owner, "listener_agent": listener, "title": "Bench", "artist_name": "Bench",
        "track_key": f"{owner}:{'b' * 32}", "duration_ms": args.seconds * 1000})
    app.library.set_grant(fid, issue_personal_licence(
        owner_signer=artist, owner_agent=owner, listener_agent=listener,
        recipient_public=bytes.fromhex(app.keys.listener_public_hex()), signed_manifest=manifest,
        content_key=key), "perpetual-personal")
    app.library.verify_complete(fid)
    p = app.player
    samples: list[tuple[float, str, int]] = []
    stop = threading.Event()

    def sampler():
        while not stop.is_set():
            s = p.status()
            samples.append((time.perf_counter(), s["state"], s["position_frames"]))
            time.sleep(0.05)
    t_play = time.perf_counter()
    p.play(fid)
    while not WRITES:
        time.sleep(0.005)
    first_play_ms = (WRITES[0][0] - t_play) * 1000
    threading.Thread(target=sampler, daemon=True).start()
    time.sleep(1.0)
    rng = random.Random(7)
    total = p.status()["total_frames"]
    lat, marks = [], []
    for _ in range(args.seeks):
        target = rng.randrange(0, total - RATE * 10)
        with _lock:
            n_before = len(WRITES)
            last_id = WRITES[-1][1] if WRITES else 0
        t0 = time.perf_counter()
        p.seek(target)
        marks.append(t0)
        metrics = None if args.writes_only else getattr(p, "seek_metrics", None)
        deadline = t0 + 15
        got = None
        while time.perf_counter() < deadline and got is None:
            if metrics is not None:
                m = p.seek_metrics()
                if m and m[-1].get("requested_at") and m[-1]["requested_at"] >= t0 and m[-1].get("first_output_at"):
                    got = (m[-1]["first_output_at"] - t0) * 1000
            else:
                with _lock:
                    new = [w for w in WRITES[n_before:] if w[1] != last_id]
                if new:
                    got = (new[0][0] - t0) * 1000
            time.sleep(0.002)
        lat.append(got if got is not None else float("inf"))
        time.sleep(args.interval)
    stop.set()
    p.stop()
    app.stop()
    # Position quality while state says playing.
    backwards = 0
    longest_static = 0.0
    run_start = None
    for (t1, s1, f1), (t2, s2, f2) in zip(samples, samples[1:]):
        seek_between = any(t1 <= m <= t2 for m in marks)
        if s1 == s2 == "playing" and not seek_between:
            if f2 < f1:
                backwards += 1
            if f2 == f1:
                run_start = run_start or t1
                longest_static = max(longest_static, t2 - run_start)
            else:
                run_start = None
        else:
            run_start = None
    states = sorted({s for _, s, _ in samples})
    finite = sorted(x for x in lat if x != float("inf"))
    q = statistics.quantiles(finite, n=20) if len(finite) >= 2 else finite
    report = {"track_seconds": args.seconds, "seeks": args.seeks, "timeouts": lat.count(float("inf")),
              "first_play_ms": round(first_play_ms, 1),
              "seek_ms_median": round(statistics.median(finite), 1), "seek_ms_p95": round(q[-1], 1),
              "seek_ms_max": round(max(finite), 1), "seek_ms_all": [round(x, 1) for x in lat],
              "position_backwards_while_playing": backwards,
              "longest_static_position_while_playing_s": round(longest_static, 2), "states_seen": states}
    print(json.dumps(report, indent=1))
    if args.json:
        Path(args.json).write_text(json.dumps(report))
    import shutil
    shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
