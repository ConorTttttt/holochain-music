#!/usr/bin/env python3
"""HWC compatibility patch (foundation, INERT): call_remote authorisation.

Adds packages/core/src/remote-call/remote-call-auth.ts with tests against
canonical Holochain 0.7 vectors (vectors-rs/). Nothing is wired into the HWC
runtime: the gateway cannot deliver CallRemoteReq to browser agents yet, and
outgoing call_remote is still refused by HWC's `call` host function. See
docs/web/call-remote.md for the full design and the remaining work.

Usage: apply.py HWC_CHECKOUT [--check]
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = ["remote-call-auth.ts", "remote-call-auth.test.ts", "zome-call-vectors.json"]
DEST = "packages/core/src/remote-call"


def main() -> int:
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--check"):
        print(__doc__, file=sys.stderr)
        return 2
    dest = Path(sys.argv[1]) / DEST
    if dest.exists():
        print(f"ALREADY_PRESENT {DEST}", file=sys.stderr)
        return 1
    if len(sys.argv) == 2:
        dest.mkdir(parents=True)
        for name in FILES:
            shutil.copyfile(HERE / name, dest / name)
    print(f"HWC_REMOTE_CALL_AUTH={'CHECK' if len(sys.argv) == 3 else 'WRITE'} files={len(FILES)} wired=no")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
