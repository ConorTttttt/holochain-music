#!/usr/bin/env python3
"""HWC compatibility patch: standard Holochain call_remote (bidirectional).

Copies into packages/core/src/remote-call/:
  remote-call-auth.ts       native-order authoriser (decode, SHA-512 signature,
                            cell, nonce witness, CapGrant::is_valid)
  remote-call-runtime.ts    outgoing signing, ZomeCallResponse codec, live
                            grants from the source chain, incoming outcomes
  *.test.ts + zome-call-vectors.json (canonical Holochain 0.7 vectors)
then applies runtime.patch (git apply, exact context):
  ribosome/host-fn/call.ts  CallTarget::NetworkAgent -> sign -> gateway
  ribosome/index.ts         callZomeRemote(): the ONLY path that may execute
                            with a foreign provenance, after authorisation
  storage/sqlite-schema.ts  persistent remote_call_nonces table
  network/websocket-service.ts, offscreen/index.ts, offscreen/ribosome-worker.ts
                            call_remote_incoming / call_remote_response frames,
                            persistent witness, POST /call_remote transport

Apply AFTER Imposter's patches, multi-cell routing and record verification.
Usage: apply.py HWC_CHECKOUT [--check]
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = ["remote-call-auth.ts", "remote-call-auth.test.ts", "remote-call-runtime.ts",
         "remote-call-runtime.test.ts", "zome-call-vectors.json"]
DEST = "packages/core/src/remote-call"
PATCH = HERE / "runtime.patch"


def main() -> int:
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--check"):
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    dest = root / DEST
    if dest.exists():
        print(f"ALREADY_PRESENT {DEST}", file=sys.stderr)
        return 1
    subprocess.run(["git", "-C", str(root), "apply", "--check", str(PATCH)], check=True)
    if len(sys.argv) == 2:
        dest.mkdir(parents=True)
        for name in FILES:
            shutil.copyfile(HERE / name, dest / name)
        subprocess.run(["git", "-C", str(root), "apply", str(PATCH)], check=True)
    mode = "CHECK" if len(sys.argv) == 3 else "WRITE"
    print(f"HWC_REMOTE_CALL={mode} files={len(FILES)} wired=yes outgoing=NetworkAgent incoming=authorised")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
