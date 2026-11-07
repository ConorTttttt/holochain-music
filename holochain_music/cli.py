"""`holochain-music` launcher and maintenance commands."""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import signal
import sys
import threading

from music_catalogue.audio_output import available_backends

from . import __version__


def _passphrase(confirm: bool) -> str:
    env = os.environ.get("HOLOCHAIN_MUSIC_BACKUP_PASSPHRASE")
    if env:
        return env
    first = getpass.getpass("Backup passphrase: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != first:
        sys.exit("passphrases do not match")
    return first


def _read_session(paths) -> dict | None:
    """The running instance's private UI link (same protection as the keys)."""
    try:
        info = json.loads(paths.session_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    url = info.get("url") if isinstance(info, dict) else None
    if not isinstance(url, str) or not url.startswith("http://127.0.0.1:") or "#token=" not in url:
        return None
    return info


def _open_browser(url: str) -> None:
    import webbrowser
    webbrowser.open(url)


def cmd_start(args) -> int:
    from .app import AlreadyRunning, MusicApp
    from .library import _atomic_json
    from .server import serve
    app = MusicApp()
    if args.audio:
        app.save_settings(audio_backend=args.audio)
        app.player.backend = args.audio
    print("Starting Holochain Music", __version__, "…", flush=True)
    try:
        app.start(offline=args.offline)
    except AlreadyRunning as exc:
        # Launching again (e.g. from the Start menu or the desktop entry)
        # re-opens the running instance instead of failing silently.
        session = _read_session(app.paths)
        if session and not args.no_browser:
            _open_browser(session["url"])
            print("Holochain Music is already running; opened it in your browser.", flush=True)
            return 0
        print(exc, file=sys.stderr)
        return 1
    # A GUI launch has no console. Keep native device diagnostics in a bounded
    # per-user file; this logger never receives grants, keys, or PCM.
    import logging
    from logging.handlers import RotatingFileHandler
    audio_log = logging.getLogger("music_catalogue.audio_output")
    handler = RotatingFileHandler(app.paths.logs / "audio.log", maxBytes=1_000_000,
                                  backupCount=2, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(threadName)s] %(message)s"))
    audio_log.addHandler(handler)
    audio_log.setLevel(logging.INFO)
    print("Status:", app.status_message, flush=True)
    server, url = serve(app, port=args.port)
    _atomic_json(app.paths.session_file, {"url": url, "pid": os.getpid(), "version": __version__})
    print("Open this private link in a browser on THIS computer (do not share it):", flush=True)
    print(url, flush=True)
    stop = app.shutdown_requested
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    if hasattr(signal, "SIGBREAK"):  # Windows console Ctrl+Break / window close
        signal.signal(signal.SIGBREAK, lambda *_: stop.set())
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    thread.start()
    if not args.no_browser:
        _open_browser(url)
    try:
        while not stop.wait(0.5):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        print("Shutting down…", flush=True)
        app.paths.session_file.unlink(missing_ok=True)
        server.shutdown()
        server.server_close()
        try:
            app.stop()
        finally:
            audio_log.removeHandler(handler)
            handler.close()
    return 0


def cmd_open(args) -> int:
    from .paths import AppPaths
    session = _read_session(AppPaths.default())
    if not session:
        print("Holochain Music is not running.", file=sys.stderr)
        return 1
    _open_browser(session["url"])
    return 0


def cmd_quit(args) -> int:
    """Ask the running instance to shut down cleanly (Start-menu "Quit")."""
    import http.client
    from urllib.parse import urlsplit
    from .paths import AppPaths
    session = _read_session(AppPaths.default())
    if not session:
        print("Holochain Music is not running.")
        return 0
    parts = urlsplit(session["url"])
    token = parts.fragment[len("token="):]
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    try:
        conn.request("POST", "/api/shutdown", body=b"{}", headers={
            "Authorization": f"Bearer {token}", "Content-Type": "application/json",
            "Origin": f"http://127.0.0.1:{parts.port}", "Host": f"127.0.0.1:{parts.port}"})
        ok = conn.getresponse().status == 200
    except OSError:
        ok = False
    finally:
        conn.close()
    print("Holochain Music is shutting down." if ok else "Could not reach Holochain Music.")
    return 0 if ok else 1


def cmd_audio_devices(args) -> int:
    from music_catalogue.audio_output import WASAPI, list_output_devices
    if sys.platform != "win32":
        print("Linux uses ALSA device names (see `aplay -L`), e.g. default, plughw:0,0")
        return 0
    for row in list_output_devices(WASAPI):
        print(row["name"])
    return 0


def cmd_backup(args) -> int:
    from .keys import export_backup, import_backup
    from .paths import AppPaths
    paths = AppPaths.default()
    if args.action == "export":
        out = export_backup(sources={"keys": paths.keys, "library": paths.library, "host": paths.host},
                            destination=Path(args.file), passphrase=_passphrase(True))
        print("Encrypted backup written to", out)
    else:
        restored = import_backup(source=Path(args.file), passphrase=_passphrase(False),
                                 targets={"keys": paths.keys, "library": paths.library, "host": paths.host})
        print("Restored:", ", ".join(restored) or "nothing")
    return 0


def cmd_status(args) -> int:
    from .paths import AppPaths
    from .library import Library
    paths = AppPaths.default()
    lib = Library(paths.library)
    rows = lib.all()
    print(json.dumps({"data_dir": str(paths.data), "library_tracks": len(rows),
                      "offline_ready": sum(1 for r in rows if r.get("complete") and r.get("grant_kind") == "perpetual-personal")},
                     indent=2))
    return 0


def cmd_bootstrap(args) -> int:
    from .conductor import BootstrapServer
    from .paths import AppPaths
    paths = AppPaths.default()
    paths.ensure()
    server = BootstrapServer(args.listen, paths.logs / "bootstrap-server.log")
    server.start()
    print(f"Bootstrap + relay listening on {args.listen}. Other computers: set bootstrap/relay URL to http://{args.listen}")
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        while not stop.wait(0.5):  # portable: Windows has no signal.sigwait
            pass
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


def cmd_config(args) -> int:
    from .app import AppError, MusicApp
    app = MusicApp()
    if args.action == "set":
        if not args.key or args.value is None:
            sys.exit("usage: holochain-music config set KEY VALUE")
        try:
            value = json.loads(args.value)  # true/false/null/numbers
        except ValueError:
            value = args.value  # plain strings such as URLs
        try:
            app.save_settings(**{args.key: value})
        except AppError as exc:
            sys.exit(f"error: {exc}")
        print("Saved. Restart Holochain Music to apply.")
    print(json.dumps({k: v for k, v in app.settings.items() if k != "pins"}, indent=2, sort_keys=True))
    return 0


def cmd_export(args) -> int:
    from .app import MusicApp
    app = MusicApp()
    app.lock()
    try:
        print("Exported", app.export_wav(args.file_id, Path(args.out)))
    finally:
        app.stop()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="holochain-music", description="Artist-first decentralised music player")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command")
    s = sub.add_parser("start", help="start the player (default)")
    s.add_argument("--offline", action="store_true", help="play your downloaded library without any network")
    s.add_argument("--no-browser", action="store_true")
    s.add_argument("--port", type=int, default=0)
    s.add_argument("--audio", choices=available_backends())
    s.set_defaults(func=cmd_start)
    b = sub.add_parser("backup", help="export or import an encrypted backup of keys and library")
    b.add_argument("action", choices=("export", "import"))
    b.add_argument("file")
    b.set_defaults(func=cmd_backup)
    sub.add_parser("status", help="show local library status").set_defaults(func=cmd_status)
    c = sub.add_parser("config", help="show or change settings (restart to apply)")
    c.add_argument("action", choices=("show", "set"))
    c.add_argument("key", nargs="?")
    c.add_argument("value", nargs="?")
    c.set_defaults(func=cmd_config)
    bs = sub.add_parser("bootstrap-server", help="run a bootstrap+relay for a private LAN")
    bs.add_argument("--listen", required=True, help="e.g. 192.168.1.50:47011")
    bs.set_defaults(func=cmd_bootstrap)
    sub.add_parser("open", help="open the running player in your browser").set_defaults(func=cmd_open)
    sub.add_parser("quit", help="shut the running player down cleanly").set_defaults(func=cmd_quit)
    sub.add_parser("audio-devices", help="list audio output devices").set_defaults(func=cmd_audio_devices)
    e = sub.add_parser("export", help="export a playable WAV (perpetual licence only)")
    e.add_argument("file_id")
    e.add_argument("out")
    e.set_defaults(func=cmd_export)
    args = p.parse_args(argv)
    if args.command is None:
        args = p.parse_args(["start", *(argv or sys.argv[1:])])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
