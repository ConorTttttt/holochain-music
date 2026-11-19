#!/usr/bin/env python3
"""HWC compatibility patch: route page zome calls to the requested cell.

Base: Holo-Host/holo-web-conductor 0c391226e78769d44ccb4661881ed8998b15f903
with the Imposter browser-alpha patches applied (apply.py,
apply_restricted_hwc_handler.py, apply_installed_hwc_receiver.py).

Problem (found by Holochain Music, which installs two roles):
    handleCallZome() always builds the cell id from `context.dnas[0]`, so a
    page can only ever reach the FIRST role of a multi-role hApp. Music's
    second role (`music_storage`: S2 key bindings, file commitments, host
    endpoints, private grant inbox) is unreachable.

Fix (generic, fail-closed, backward compatible):
    * record the hApp role name on each DnaContext at install (`roleName`);
    * a call naming `role_name` runs in exactly that role's cell (matching
      `roleName`, or the DNA name for contexts installed before this patch);
    * a call naming `cell_id` must name one of THIS origin's cells with THIS
      context's agent; anything else is refused;
    * a call naming neither keeps the previous behaviour (first DNA).
    The agent / provenance is unchanged: always the context's own agent.

Usage: apply_multi_cell_routing.py HWC_CHECKOUT [--check]
"""
from __future__ import annotations

import sys
from pathlib import Path

EDITS = [
    (
        "packages/core/src/index.ts",
        "  /** DNA name/identifier */\n  name?: string;\n",
        "  /** DNA name/identifier */\n  name?: string;\n\n"
        "  /** hApp role name this DNA was installed under (multi-cell routing) */\n  roleName?: string;\n",
    ),
    (
        "packages/extension/src/lib/happ-context-manager.ts",
        "          name: dnaBundle.manifest.name,\n          properties: effectiveProperties,",
        "          name: dnaBundle.manifest.name,\n          roleName: role.name,\n          properties: effectiveProperties,",
    ),
    (
        "packages/extension/src/background/index.ts",
        """    const agentPubKey = toUint8Array(context.agentPubKey);
    const dnaHash = toUint8Array(context.dnas[0].hash); // Use first DNA's hash
""",
        """    const agentPubKey = toUint8Array(context.agentPubKey);
    // Multi-cell routing: honour role_name / cell_id, but only within this
    // origin's own context and agent. Unknown roles or cells fail closed.
    const sameBytes = (a: Uint8Array, b: Uint8Array) =>
      a.length === b.length && a.every((byte, i) => byte === b[i]);
    let routedDna = context.dnas[0];
    const requestedRole = requestPayload.role_name;
    const requestedCell = requestPayload.cell_id;
    if (requestedRole !== undefined && requestedRole !== null) {
      if (typeof requestedRole !== "string") {
        return createErrorResponse(message.id, "Invalid role_name");
      }
      const byRole = context.dnas.filter((d: any) => (d.roleName ?? d.name) === requestedRole);
      if (byRole.length !== 1) {
        return createErrorResponse(message.id, `Unknown role_name for this hApp: ${requestedRole}`);
      }
      routedDna = byRole[0];
    }
    if (requestedCell !== undefined && requestedCell !== null) {
      if (!Array.isArray(requestedCell) || requestedCell.length !== 2) {
        return createErrorResponse(message.id, "Invalid cell_id");
      }
      const cellDna = toUint8Array(normalizeUint8Arrays(requestedCell[0]));
      const cellAgent = toUint8Array(normalizeUint8Arrays(requestedCell[1]));
      const byCell = context.dnas.find((d: any) => sameBytes(toUint8Array(d.hash), cellDna));
      if (!byCell || !sameBytes(cellAgent, agentPubKey) ||
          (requestedRole != null && byCell !== routedDna)) {
        return createErrorResponse(message.id, "cell_id is not a cell of this hApp context");
      }
      routedDna = byCell;
    }
    const dnaHash = toUint8Array(routedDna.hash);
""",
    ),
]


def main() -> int:
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--check"):
        print(__doc__, file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    check = len(sys.argv) == 3
    planned = []
    for rel, old, new in EDITS:
        path = root / rel
        text = path.read_text(encoding="utf-8")
        if text.count(old) != 1:
            if text.count(new) == 1:
                print(f"ALREADY_APPLIED {rel}")
                continue
            print(f"ANCHOR_MISMATCH {rel}", file=sys.stderr)
            return 1
        planned.append((path, text.replace(old, new)))
    if not check:
        for path, text in planned:
            path.write_text(text, encoding="utf-8")
    print(f"HWC_MULTI_CELL_ROUTING={'CHECK' if check else 'WRITE'} files={len(planned)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
