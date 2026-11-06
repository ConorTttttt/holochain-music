#!/usr/bin/env python3
"""Measure publish -> listener-discovery latency with two fresh app instances.

    PYTHONPATH=. python packaging/measure-discovery.py OUTFILE TRIALS POLL_MAX_MS [POLL_MAX_MS ...]

Each trial: new artist + listener homes, shared fresh loopback bootstrap, both
started together, artist publishes a 1 s tone, then the listener's catalogue is
polled every second. Settings are interleaved trial by trial. One computer only.
"""
import json, shutil, socket, sys, tempfile, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
from holochain_music.app import MusicApp
from holochain_music.paths import AppPaths
from v1_fixtures import write_tone

out, trials, settings = Path(sys.argv[1]), int(sys.argv[2]), [int(x) for x in sys.argv[3:]]
for trial in range(trials):
    for poll_max in settings:
        base = Path(tempfile.mkdtemp(prefix="hmd-", dir="/mnt/holochain/tmp/disc"))
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
        apps = []
        row = {"trial": trial, "poll_max_ms": poll_max}
        try:
            for name in ("artist", "listener"):
                a = MusicApp(AppPaths(data=base / name / "data", config=base / name / "config"))
                a.save_settings(bootstrap_url=f"http://127.0.0.1:{port}", relay_url=f"http://127.0.0.1:{port}",
                                audio_backend="null", bootstrap_poll_max_ms=poll_max)
                apps.append(a)
            t0 = time.monotonic()
            for a in apps:
                a.start()
            row["online_s"] = round(time.monotonic() - t0, 1)
            artist, listener = apps
            write_tone(base / "t.wav", seconds=1.0)
            r = artist.publish_track(wav=base / "t.wav", title="Discovery probe")
            key = f"{artist.agent}:{r['track_id']}"
            t1 = time.monotonic()
            row["discovery_s"] = None
            while time.monotonic() - t1 < 700:
                try:
                    if any(t["key"] == key for t in listener.catalogue.browse()):
                        row["discovery_s"] = round(time.monotonic() - t1, 1)
                        break
                except Exception:
                    pass
                time.sleep(1)
        except Exception as exc:
            row["error"] = repr(exc)[:200]
        finally:
            for a in apps:
                a.stop()
            shutil.rmtree(base, ignore_errors=True)
        with out.open("a") as f:
            f.write(json.dumps(row) + "\n")
