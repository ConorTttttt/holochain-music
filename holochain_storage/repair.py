"""Conservative local replica repair using a fully verified encrypted source.

Not networked. If a node fails an audit, this demonstrates how to replace
missing or corrupt ciphertext without accessing any plaintext content key.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .package import (
    StorageError, _atomic_write, _assert_manifest, _read_verified_chunk,
    _verify_signed, object_path, replicate_package, sha256, verify_package,
)


@dataclass(frozen=True)
class RepairResult:
    source: str
    missing_repaired: int
    corrupt_replaced: int
    already_valid: int
    receipt: dict


def repair_full_replica(package: dict, sources: Iterable[str | Path], destination: str | Path,
                        trusted_artist: bytes, node_private: Ed25519PrivateKey) -> RepairResult:
    """Repair a complete encrypted replica and issue a new acceptance receipt.

    Requires at least one *fully verified* independent source. Invalid source
    replicas are skipped; no decryption keys are needed. This local prototype
    does not promise atomic multi-file recovery or adversarial-filesystem safety.
    """
    manifest = _verify_signed(package, trusted_artist, "manifest")
    _assert_manifest(manifest)
    target = Path(destination)
    candidate = None
    for source in sources:
        source = Path(source)
        if source.resolve() == target.resolve():
            continue
        try:
            verify_package(package, source, trusted_artist)
        except (StorageError, OSError):
            continue
        candidate = source
        break
    if candidate is None:
        raise StorageError("no independently verified source replica for repair")
    missing, corrupted, healthy = 0, 0, 0
    for chunk in manifest["chunks"]:
        dst = object_path(target, chunk["sha256"])
        if dst.is_symlink():
            raise StorageError("refusing symlinked destination chunk")
        try:
            _read_verified_chunk(target, chunk)
            healthy += 1
            continue
        except StorageError:
            pass
        existed = dst.exists()
        verified_ciphertext = _read_verified_chunk(candidate, chunk)
        if sha256(verified_ciphertext) != chunk["sha256"]:
            raise StorageError("source ciphertext changed during repair")
        _atomic_write(dst, verified_ciphertext)
        if existed:
            corrupted += 1
        else:
            missing += 1
    verify_package(package, target, trusted_artist)
    receipt = replicate_package(package, candidate, target, trusted_artist, node_private)
    return RepairResult(str(candidate), missing, corrupted, healthy, receipt)
