"""Reusable encrypted, content-addressed full-replica storage prototype.

This package deliberately has no Holochain, MoQ, music, or payment dependency.
"""

from .package import (
    StorageError,
    create_package,
    verify_package,
    replicate_package,
    decrypt_package,
    verify_receipt,
)
from .grant import create_perpetual_grant, open_perpetual_grant

__all__ = [
    "StorageError", "create_package", "verify_package", "replicate_package",
    "decrypt_package", "verify_receipt", "create_perpetual_grant", "open_perpetual_grant",
]
