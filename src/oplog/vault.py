from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VAULT_NAME = "vault.oplog"
KDF_N, KDF_R, KDF_P = 32768, 8, 1


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def vault_path(workspace: Path) -> Path:
    return workspace / VAULT_NAME


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _key(passphrase: str, salt: bytes) -> bytes:
    if not passphrase:
        raise ValueError("Vault passphrase cannot be empty")
    return Scrypt(salt=salt, length=32, n=KDF_N, r=KDF_R, p=KDF_P).derive(passphrase.encode("utf-8"))


def _write(path: Path, passphrase: str, salt: bytes, payload: dict) -> None:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key(passphrase, salt)).encrypt(nonce, json.dumps(payload, separators=(",", ":")).encode("utf-8"), b"oplog-vault-v1")
    document = {
        "format": "oplog-vault-v1",
        "kdf": {"name": "scrypt", "n": KDF_N, "r": KDF_R, "p": KDF_P, "salt": _b64(salt)},
        "cipher": {"name": "AES-256-GCM", "nonce": _b64(nonce), "ciphertext": _b64(ciphertext)},
    }
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


def create_vault(workspace: Path, passphrase: str) -> None:
    path = vault_path(workspace)
    if path.exists():
        raise FileExistsError(f"Vault already exists: {path}")
    _write(path, passphrase, os.urandom(16), {"version": 1, "secrets": []})


def _read(workspace: Path, passphrase: str) -> tuple[Path, bytes, dict]:
    path = vault_path(workspace)
    if not path.is_file():
        raise FileNotFoundError(f"No vault found at {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("format") != "oplog-vault-v1" or document["kdf"]["name"] != "scrypt":
            raise ValueError("Unsupported vault format")
        salt = _unb64(document["kdf"]["salt"])
        nonce = _unb64(document["cipher"]["nonce"])
        ciphertext = _unb64(document["cipher"]["ciphertext"])
        cleartext = AESGCM(_key(passphrase, salt)).decrypt(nonce, ciphertext, b"oplog-vault-v1")
        payload = json.loads(cleartext.decode("utf-8"))
    except (KeyError, TypeError, ValueError, InvalidTag, json.JSONDecodeError) as error:
        raise ValueError("Vault could not be opened: incorrect passphrase or corrupted vault") from error
    return path, salt, payload


def add_secret(workspace: Path, passphrase: str, secret_type: str, label: str, value: str, source_event: int | None, expires_at: str | None) -> int:
    if not value:
        raise ValueError("Secret value cannot be empty")
    path, salt, payload = _read(workspace, passphrase)
    secrets = payload.setdefault("secrets", [])
    identifier = len(secrets) + 1
    secrets.append({"id": identifier, "created_at": utc_now(), "type": secret_type, "label": label, "value": value, "source_event": source_event, "expires_at": expires_at, "status": "active"})
    _write(path, passphrase, salt, payload)
    return identifier


def list_secrets(workspace: Path, passphrase: str) -> list[dict]:
    _, _, payload = _read(workspace, passphrase)
    fields = ("id", "created_at", "type", "label", "source_event", "expires_at", "status")
    return [{key: item.get(key) for key in fields} for item in payload.get("secrets", [])]


def get_secret(workspace: Path, passphrase: str, identifier: int) -> dict:
    _, _, payload = _read(workspace, passphrase)
    for item in payload.get("secrets", []):
        if item.get("id") == identifier:
            return item
    raise ValueError(f"Secret SEC-{identifier:04d} does not exist")


def vault_fingerprint(workspace: Path) -> str | None:
    path = vault_path(workspace)
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
