#!/usr/bin/env python3
"""HWC compatibility patch: verify DHT data returned by the gateway.

Base: Holo-Host/holo-web-conductor 0c391226e78769d44ccb4661881ed8998b15f903
with Imposter's browser-alpha patches (and optionally the Music multi-cell
routing patch). Adds packages/core/src/network/record-verification.ts and its
malicious-gateway tests, exports them, exposes the chain-recovery wire-action
normalizer, and wraps the worker's gateway NetworkService so every record,
link and details response is verified before cache, validation or WASM.

Usage: apply.py HWC_CHECKOUT [--check]
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NEW_FILES = {
    "record-verification.ts": "packages/core/src/network/record-verification.ts",
    "record-verification.test.ts": "packages/core/src/network/record-verification.test.ts",
    "fixtures/gateway-record-create.json": "packages/core/src/network/__fixtures__/gateway-record-create.json",
}
APPEND = [
    ("packages/core/src/recovery/chain-recovery.ts", "export function wireActionToSerializable(", """
/**
 * Normalize untrusted wire action content (possibly JSON-flattened byte
 * arrays) to the exact `SerializableAction` whose msgpack encoding Holochain
 * hashes and signs. Exported for network record verification.
 */
export function wireActionToSerializable(content: Action): SerializableAction {
  const flat = flatAction(content);
  if (!flat) throw new Error('missing action content');
  const action = normalizeActionContent(flat) as unknown as { data: { entry_type?: unknown } };
  // Gateways serialise via serde_json::Value, which sorts map keys. Msgpack
  // map order is part of the hashed/signed bytes, so restore Rust's
  // AppEntryDef declaration order { entry_index, zome_index, visibility }.
  const et = action.data.entry_type as { App?: Record<string, unknown> } | undefined;
  if (et && typeof et === 'object' && et.App) {
    const { entry_index, zome_index, visibility } = et.App;
    action.data.entry_type = { App: { entry_index, zome_index, visibility } };
  }
  return action as unknown as SerializableAction;
}
"""),
    ("packages/core/src/network/index.ts", "withRecordVerification,", """
// Verification of untrusted gateway responses (Holochain Music web compatibility patch)
export {
  withRecordVerification,
  verifyNetworkRecord,
  verifyNetworkLink,
  verifySignedAction,
  verifyDetails,
  computeNetworkEntryHash,
  UnverifiedNetworkDataError,
  type VerificationRejectHandler,
} from './record-verification';
"""),
]
EDITS = [
    ("packages/extension/src/offscreen/ribosome-worker.ts",
     "import { setNetworkService, NetworkError, isNetworkError, type NetworkService,",
     "import { setNetworkService, withRecordVerification, NetworkError, isNetworkError, type NetworkService,"),
    ("packages/extension/src/offscreen/ribosome-worker.ts",
     "        setNetworkService(networkService);\n",
     "        // Every record/link/details response from the gateway is verified before use.\n"
     "        setNetworkService(withRecordVerification(networkService));\n"),
    ("packages/extension/src/offscreen/ribosome-worker.ts",
     """        tag,
        timestamp: create.timestamp,
        author,
      };
    });
  }""",
     """        tag,
        timestamp: create.timestamp,
        author,
        // Signed CreateLink fields: the verifier recomputes the real
        // create_link_hash and checks the author's signature.
        prev_action: prevAction,
        action_seq: create.action_seq,
        signature: create.signature ? this.normalizeByteArrays(create.signature) : undefined,
      };
    });
  }"""),
]


def main() -> int:
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--check"):
        print(__doc__, file=sys.stderr)
        return 2
    root, check = Path(sys.argv[1]), len(sys.argv) == 3
    texts: dict[Path, str] = {}

    def text(rel: str) -> str:
        path = root / rel
        if path not in texts:
            texts[path] = path.read_text(encoding="utf-8")
        return texts[path]

    for _src, dst in NEW_FILES.items():
        if (root / dst).exists():
            print(f"ALREADY_PRESENT {dst}", file=sys.stderr)
            return 1
    for rel, marker, block in APPEND:
        if marker in text(rel):
            print(f"ALREADY_APPLIED {rel}", file=sys.stderr)
            return 1
        texts[root / rel] = text(rel) + block
    for rel, old, new in EDITS:
        if text(rel).count(old) != 1:
            print(f"ANCHOR_MISMATCH {rel}: {old.splitlines()[0][:60]}", file=sys.stderr)
            return 1
        texts[root / rel] = text(rel).replace(old, new)
    if not check:
        for src, dst in NEW_FILES.items():
            (root / dst).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(HERE / src, root / dst)
        for path, body in texts.items():
            path.write_text(body, encoding="utf-8")
    print(f"HWC_RECORD_VERIFICATION={'CHECK' if check else 'WRITE'} new={len(NEW_FILES)} edited={len(texts)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
