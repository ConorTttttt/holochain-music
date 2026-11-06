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

from . import __version__


def _passphrase(confirm: bool) -> str:
    env = os.environ.get("HOLOCHAIN_MUSIC_BACKUP_PASSPHRASE")
    if env:
        return env
    first = getpass.getpass("Backup passphrase: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != first:
        sys.exit("passphrases do not match")
    return first


def cmd_start(args) -> int:
    from .app import AlreadyRunning, MusicApp
    from .server import serve
    app = MusicApp()
    if args.audio:
        app.save_settings(audio_backend=args.audio)
        app.player.backend = args.audio
    print("Starting Holochain Music", __version__, "…", flush=True)
    try:
        app.start(offline=args.offline)
    except AlreadyRunning as exc:
        print(exc, file=sys.stderr)
        return 1
    print("Status:", app.status_message, flush=True)
    server, url = serve(app, port=args.port)
    print("Open this private link in a browser on THIS computer (do not share it):", flush=True)
    print(url, flush=True)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    thread.start()
    if not args.no_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        while not stop.wait(0.5):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        print("Shutting down…", flush=True)
        server.shutdown()
        server.server_close()
        app.stop()
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
    try:
        signal.sigwait({signal.SIGINT, signal.SIGTERM})
    finally:
        server.stop()
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
    s.add_argument("--audio", choices=("alsa", "null"))
    s.set_defaults(func=cmd_start)
    b = sub.add_parser("backup", help="export or import an encrypted backup of keys and library")
    b.add_argument("action", choices=("export", "import"))
    b.add_argument("file")
    b.set_defaults(func=cmd_backup)
    sub.add_parser("status", help="show local library status").set_defaults(func=cmd_status)
    bs = sub.add_parser("bootstrap-server", help="run a bootstrap+relay for a private LAN")
    bs.add_argument("--listen", required=True, help="e.g. 192.168.1.50:47011")
    bs.set_defaults(func=cmd_bootstrap)
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
