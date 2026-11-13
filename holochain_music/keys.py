"""Local secret storage and passphrase-protected backups.

Secrets are raw key files inside a 0700 directory, each created 0600 with
O_EXCL and never followed through symlinks — the same model as OpenSSH and
GnuPG home directories. On Windows the directory carries a protected DACL
(current user + SYSTEM only) that every key file inherits, and reads refuse
files whose DACL grants any other account (see holochain_storage.portable). They protect against other local users, not against
malware running as this user or theft of an unlocked disk. Use full-disk
encryption; see docs/security-model.md.

Backups are a tar archive encrypted with the existing S1 chunked AES-256-GCM
package format; only the package key is wrapped, with AES-256-GCM under a
scrypt-derived key. No custom primitives.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import tarfile
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from holochain_storage import portable
from holochain_storage.package import (
    b64, canonical, create_package, decrypt_package, from_b64, public_key_bytes,
)

BACKUP_SCHEMA = "holochain-music/backup/v1"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**17, 8, 1
MIN_PASSPHRASE = 10
MAX_BACKUP_MEMBERS = 200_000


class KeyStoreError(RuntimeError):
    pass


def _read_secret(path: Path, size: int) -> bytes:
    try:
        info = portable.check_secret_file(path)
    except portable.PortabilityError as exc:
        raise KeyStoreError(str(exc)) from exc
    if info.st_size != size:
        raise KeyStoreError(f"key file {path.name} has the wrong size")
    fd = os.open(path, os.O_RDONLY | portable.O_NOFOLLOW | portable.O_BINARY | portable.O_NOINHERIT)
    with os.fdopen(fd, "rb") as f:
        return f.read()


def _write_secret(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | portable.O_NOFOLLOW | portable.O_BINARY
                 | portable.O_NOINHERIT, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


class KeyStore:
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        try:
            portable.make_private_dir(self.dir)
        except portable.PortabilityError as exc:
            raise KeyStoreError("refusing symlinked key directory") from exc

    def _get_or_create(self, name: str, size: int, factory) -> bytes:
        path = self.dir / name
        try:
            return _read_secret(path, size)
        except FileNotFoundError:
            value = factory()
            try:
                _write_secret(path, value)
            except FileExistsError:
                return _read_secret(path, size)
            return value

    def listener_x25519(self) -> X25519PrivateKey:
        raw = self._get_or_create("listener.x25519", 32, lambda: X25519PrivateKey.generate().private_bytes_raw())
        return X25519PrivateKey.from_private_bytes(raw)

    def listener_public_hex(self) -> str:
        return self.listener_x25519().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def artist_ed25519(self) -> Ed25519PrivateKey:
        raw = self._get_or_create("artist.ed25519", 32, lambda: Ed25519PrivateKey.generate().private_bytes_raw())
        return Ed25519PrivateKey.from_private_bytes(raw)

    def host_ed25519(self) -> Ed25519PrivateKey:
        raw = self._get_or_create("host.ed25519", 32, lambda: Ed25519PrivateKey.generate().private_bytes_raw())
        return Ed25519PrivateKey.from_private_bytes(raw)

    def lifecycle_ed25519(self, role: str, generation: int, *, create: bool = False) -> Ed25519PrivateKey:
        """S2 v2.1 opt-in: the signing key of one lifecycle generation.

        Generation 1 IS the existing ``artist.ed25519``/``host.ed25519`` file
        (no key migration). Later generations live in separate files that are
        created only explicitly, BEFORE their rotation is published, so a
        published key is never lost by a crash. Never sent to a zome."""
        if role not in ("artist", "host") or type(generation) is not int or not 1 <= generation <= 1_000_000:
            raise KeyStoreError("invalid lifecycle key reference")
        if generation == 1:
            return self.artist_ed25519() if role == "artist" else self.host_ed25519()
        name = f"{role}.g{generation}.ed25519"
        if create:
            raw = self._get_or_create(name, 32, lambda: Ed25519PrivateKey.generate().private_bytes_raw())
        else:
            try:
                raw = _read_secret(self.dir / name, 32)
            except FileNotFoundError as exc:
                raise KeyStoreError(f"no {role} key for lifecycle generation {generation} on this device") from exc
        return Ed25519PrivateKey.from_private_bytes(raw)

    def conductor_passphrase(self) -> bytes:
        # Unlocks the conductor's lair keystore without an interactive
        # prompt. Same protection boundary as the other key files.
        return self._get_or_create("conductor.passphrase", 43,
                                   lambda: secrets.token_urlsafe(32).encode("ascii"))

    def _content_path(self, file_id: str) -> Path:
        if len(file_id) != 64 or any(c not in "0123456789abcdef" for c in file_id):
            raise KeyStoreError("invalid file ID")
        return self.dir / "content" / f"{file_id}.aes256"

    def save_content_key(self, file_id: str, key: bytes) -> None:
        """Artist-only: needed to issue future grants for this track."""
        if len(key) != 32:
            raise KeyStoreError("invalid content key")
        content = self.dir / "content"
        content.mkdir(exist_ok=True)
        portable.make_private_dir(content)
        _write_secret(self._content_path(file_id), key)

    def content_key(self, file_id: str) -> bytes:
        try:
            return _read_secret(self._content_path(file_id), 32)
        except FileNotFoundError as exc:
            raise KeyStoreError("no content key for this track on this device") from exc


def _wrap_key(passphrase: str, key: bytes) -> dict:
    if not isinstance(passphrase, str) or len(passphrase) < MIN_PASSPHRASE:
        raise KeyStoreError(f"backup passphrase must have at least {MIN_PASSPHRASE} characters")
    salt, nonce = os.urandom(16), os.urandom(12)
    kek = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(passphrase.encode())
    return {"kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": b64(salt),
            "nonce": b64(nonce), "wrapped_key": b64(AESGCM(kek).encrypt(nonce, key, BACKUP_SCHEMA.encode()))}


def _unwrap_key(passphrase: str, info: dict) -> bytes:
    if info.get("kdf") != "scrypt" or (info.get("n"), info.get("r"), info.get("p")) != (SCRYPT_N, SCRYPT_R, SCRYPT_P):
        raise KeyStoreError("unsupported backup key-derivation parameters")
    kek = Scrypt(salt=from_b64(info["salt"], 16), length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(passphrase.encode())
    try:
        return AESGCM(kek).decrypt(from_b64(info["nonce"], 12), from_b64(info["wrapped_key"], 48), BACKUP_SCHEMA.encode())
    except InvalidTag as exc:
        raise KeyStoreError("wrong passphrase or damaged backup") from exc


def export_backup(*, sources: dict[str, Path], destination: Path, passphrase: str) -> Path:
    """Encrypt the named directories into one backup file (a tar container
    holding an S1-encrypted tar). `sources` maps archive names to paths."""
    destination = Path(destination)
    with tempfile.TemporaryDirectory(prefix="hm-backup-") as tmp:
        work = Path(tmp)
        inner = work / "inner.tar"
        with tarfile.open(inner, "w") as tar:
            for name, path in sources.items():
                if Path(path).exists():
                    tar.add(path, arcname=name, recursive=True)
        signer = Ed25519PrivateKey.generate()  # format requires a signer; integrity comes from GCM
        manifest, key = create_package(inner, work / "cas", signer)
        header = {"schema": BACKUP_SCHEMA, "signer_hex": public_key_bytes(signer).hex(), **_wrap_key(passphrase, key)}
        temp = destination.with_name(destination.name + ".partial")
        with tarfile.open(temp, "w") as outer:
            for arcname, payload in (("backup.json", canonical(header)), ("manifest.json", canonical(manifest))):
                info = tarfile.TarInfo(arcname)
                info.size = len(payload)
                outer.addfile(info, io.BytesIO(payload))
            outer.add(work / "cas", arcname="cas")
        portable.make_private_file(temp)
        portable.replace(temp, destination)
    return destination


def _safe_members(tar: tarfile.TarFile, allowed_roots: set[str]):
    members = tar.getmembers()
    if len(members) > MAX_BACKUP_MEMBERS:
        raise KeyStoreError("backup has too many entries")
    for m in members:
        p = PurePosixPath(m.name)
        if p.is_absolute() or ".." in p.parts or not p.parts or p.parts[0] not in allowed_roots:
            raise KeyStoreError(f"unsafe path in backup: {m.name}")
        if not (m.isfile() or m.isdir()):
            raise KeyStoreError("backup may contain only regular files and directories")
    return members


def import_backup(*, source: Path, passphrase: str, targets: dict[str, Path]) -> list[str]:
    """Decrypt and restore into *empty or missing* target directories only.
    Never overwrites existing user data (returns restored archive names)."""
    for name, path in targets.items():
        if Path(path).exists() and any(Path(path).iterdir()):
            raise KeyStoreError(f"refusing to overwrite existing data in {path}; move it aside first")
    with tempfile.TemporaryDirectory(prefix="hm-restore-") as tmp:
        work = Path(tmp)
        with tarfile.open(source, "r") as outer:
            outer.extractall(work, members=_safe_members(outer, {"backup.json", "manifest.json", "cas"}),
                             filter="data")
        header = json.loads((work / "backup.json").read_text(encoding="utf-8"))
        if header.get("schema") != BACKUP_SCHEMA:
            raise KeyStoreError("not a Holochain Music backup")
        key = _unwrap_key(passphrase, header)
        manifest = json.loads((work / "manifest.json").read_text(encoding="utf-8"))
        inner = decrypt_package(manifest, work / "cas", work / "inner.tar", key, bytes.fromhex(header["signer_hex"]))
        restored = []
        with tarfile.open(inner, "r") as tar:
            members = _safe_members(tar, set(targets))
            staging = work / "out"
            tar.extractall(staging, members=members, filter="data")
        for name, path in targets.items():
            if (staging / name).exists():
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                if Path(path).exists():
                    Path(path).rmdir()
                shutil.move(str(staging / name), str(path))
                portable.make_private_dir(Path(path))
                if not portable.IS_WINDOWS:  # Windows: the DACL above propagates to children
                    for f in Path(path).rglob("*"):
                        f.chmod(0o700 if f.is_dir() else 0o600)
                restored.append(name)
        return restored
