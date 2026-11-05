"""Reusable encrypted, content-addressed full-replica storage prototype.

No Holochain, MoQ, music, or payment dependency in this package.
"""

from .package import (
    StorageError, create_package, verify_package, replicate_package,
    decrypt_package, verify_receipt,
)
from .grant import create_perpetual_grant, open_perpetual_grant
from .audit import AuditVerifier, AuditResult, make_challenge, answer_challenge, verify_challenge_response
from .repair import RepairResult, repair_full_replica

__all__ = [
    "StorageError", "create_package", "verify_package", "replicate_package",
    "decrypt_package", "verify_receipt", "create_perpetual_grant", "open_perpetual_grant",
    "AuditVerifier", "AuditResult", "make_challenge", "answer_challenge",
    "verify_challenge_response", "RepairResult", "repair_full_replica",
]
