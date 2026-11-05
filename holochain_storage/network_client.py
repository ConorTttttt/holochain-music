"""S4 signed HTTP transport for the generic S1 encrypted-file package.

Prototype only: default loopback HTTP, not TLS, not Holochain-identity aware.
Never send a content key to the storage service. This module signs only
requests that mutate encrypted data and verifies replies using S1 primitives.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .package import (
    StorageError, canonical, manifest_digest, object_path, public_key_bytes,
    verify_package, verify_receipt,
)

MAX_RESPONSE_BYTES = 8 * 1024 * 1024 + 4096


class RemoteStorageError(StorageError):
    """Remote node refused the request or replied with invalid content."""


class StorageNodeClient:
    def __init__(self, base_url: str, owner_key: Ed25519PrivateKey, *, timeout: float = 15):
        if not base_url.startswith("http://127.0.0.1:") and not base_url.startswith("http://localhost:"):
            if not base_url.startswith("https://"):
                raise ValueError("remote storage node requires HTTPS or a localhost SSH tunnel")
        self.base_url = base_url.rstrip("/")
        self.owner_key = owner_key
        self.timeout = timeout

    def _request(self, method: str, path: str, body: bytes = b"", *, signed: bool = False) -> bytes:
        headers = {}
        if signed:
            timestamp = str(int(time.time()))
            nonce = os.urandom(16).hex()
            digest = hashlib.sha256(body).hexdigest()
            payload = f"holochain-storage/http-auth/v1\n{method}\n{path}\n{timestamp}\n{nonce}\n{digest}".encode()
            headers.update({
                "X-HS-Artist-Key": base64.b64encode(public_key_bytes(self.owner_key)).decode(),
                "X-HS-Timestamp": timestamp,
                "X-HS-Nonce": nonce,
                "X-HS-Body-SHA256": digest,
                "X-HS-Signature": base64.b64encode(self.owner_key.sign(payload)).decode(),
            })
        req = Request(self.base_url + path, data=body if method != "GET" else None,
                      headers=headers, method=method)
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                data = resp.read(MAX_RESPONSE_BYTES + 1)
                if len(data) > MAX_RESPONSE_BYTES:
                    raise RemoteStorageError("response too large")
                return data
        except HTTPError as exc:
            message = exc.read(4096).decode(errors="replace")
            raise RemoteStorageError(f"remote HTTP {exc.code}: {message}") from exc

    def init(self, signed_manifest: dict) -> dict:
        body = canonical({"manifest": signed_manifest})
        response = self._request("POST", "/v1/packages/init", body, signed=True)
        result = json.loads(response)
        if result.get("file_id") != signed_manifest["body"]["file_id"]:
            raise RemoteStorageError("node returned wrong file ID")
        return result

    def upload(self, signed_manifest: dict, source_store: Path) -> None:
        """Upload only AES-GCM ciphertext chunks from a locally verified S1 package."""
        verify_package(signed_manifest, source_store, public_key_bytes(self.owner_key))
        file_id = signed_manifest["body"]["file_id"]
        self.init(signed_manifest)
        for chunk in signed_manifest["body"]["chunks"]:
            data = object_path(source_store, chunk["sha256"]).read_bytes()
            path = f"/v1/packages/{file_id}/chunks/{chunk['index']}"
            self._request("PUT", path, data, signed=True)

    def commit(self, signed_manifest: dict, trusted_node: bytes) -> dict:
        file_id = signed_manifest["body"]["file_id"]
        response = self._request("POST", f"/v1/packages/{file_id}/commit", signed=True)
        receipt = json.loads(response)
        verify_receipt(receipt, signed_manifest, trusted_node, public_key_bytes(self.owner_key))
        return receipt

    def fetch(self, signed_manifest: dict, target_store: Path, trusted_node: bytes) -> None:
        """Download and verify the full encrypted replica. Does not decrypt it."""
        file_id = signed_manifest["body"]["file_id"]
        received = json.loads(self._request("GET", f"/v1/packages/{file_id}/manifest"))
        if manifest_digest(received) != manifest_digest(signed_manifest):
            raise RemoteStorageError("downloaded manifest does not match pinned signed package")
        receipt = json.loads(self._request("GET", f"/v1/packages/{file_id}/receipt"))
        verify_receipt(receipt, signed_manifest, trusted_node, public_key_bytes(self.owner_key))
        target_store = Path(target_store)
        for chunk in signed_manifest["body"]["chunks"]:
            path = f"/v1/packages/{file_id}/chunks/{chunk['index']}"
            data = self._request("GET", path)
            if len(data) != chunk["cipher_bytes"] or hashlib.sha256(data).hexdigest() != chunk["sha256"]:
                raise RemoteStorageError(f"invalid remote ciphertext chunk {chunk['index']}")
            dest = object_path(target_store, chunk["sha256"])
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.is_symlink():
                raise RemoteStorageError("refusing symlinked destination")
            if dest.exists() and (dest.stat().st_size != len(data) or hashlib.sha256(dest.read_bytes()).hexdigest() != chunk["sha256"]):
                raise RemoteStorageError("refusing to replace corrupt local object")
            if not dest.exists():
                from tempfile import NamedTemporaryFile
                import os
                with NamedTemporaryFile(dir=dest.parent, prefix=".incoming-", delete=False) as tmp:
                    path_tmp = Path(tmp.name)
                    try:
                        tmp.write(data)
                        tmp.flush()
                        os.fsync(tmp.fileno())
                    except BaseException:
                        path_tmp.unlink(missing_ok=True)
                        raise
                os.replace(path_tmp, dest)
        verify_package(signed_manifest, target_store, public_key_bytes(self.owner_key))
