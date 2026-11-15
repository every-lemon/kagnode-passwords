"""Server-only Account vault key client and backward-compatible emergency wrapping.

KagNode's key service is trusted to unlock enrolled vaults. No key or grant from
this module belongs in a browser response, URL, log or source repository.
"""

from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def encode(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def decode(value):
    if not isinstance(value, str) or len(value) > 8192:
        raise ValueError("Invalid protected key response")
    return base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )


def wrap_emergency(vault_key, password_key):
    if len(base64.urlsafe_b64decode(vault_key)) != 32:
        raise ValueError("Invalid vault key")
    return Fernet(password_key).encrypt(vault_key)


def unwrap_emergency(password_key, wrapped=None):
    """Legacy vaults used the derived password key directly; never reset them."""
    key = password_key if wrapped is None else Fernet(password_key).decrypt(wrapped)
    if len(base64.urlsafe_b64decode(key)) != 32:
        raise InvalidToken()
    return key


class VaultKeys:
    def __init__(self, directory, profiles, *, allow_create=True):
        self.profiles = profiles
        directory = Path(directory)
        if not directory.is_absolute():
            raise ValueError("Use an absolute installation key directory")
        for parent in directory.parents:
            if not parent.exists():
                continue
            meta = parent.lstat()
            sticky_tmp = parent == Path("/tmp") and bool(meta.st_mode & stat.S_ISVTX)
            if (
                not stat.S_ISDIR(meta.st_mode)
                or (meta.st_mode & 0o022 and not sticky_tmp)
                or meta.st_uid not in (0, os.geteuid())
            ):
                raise ValueError("Installation key ancestors must be protected")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        meta = directory.lstat()
        if (
            not stat.S_ISDIR(meta.st_mode)
            or meta.st_uid != os.geteuid()
            or meta.st_mode & 0o077
        ):
            raise ValueError("Installation key storage must be private")
        self.path = directory / "installation-x25519.key"
        try:
            if not allow_create:
                raise FileExistsError()
            descriptor = os.open(
                self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, "wb") as file:
                value = X25519PrivateKey.generate().private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
                file.write(value)
                file.flush()
                os.fsync(file.fileno())
        descriptor = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as file:
            meta = os.fstat(file.fileno())
            if (
                not stat.S_ISREG(meta.st_mode)
                or meta.st_uid != os.geteuid()
                or meta.st_nlink != 1
                or meta.st_mode & 0o077
                or meta.st_size != 32
            ):
                raise ValueError("Invalid private installation key")
            self.private = X25519PrivateKey.from_private_bytes(file.read(33))
        self.public = encode(
            self.private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        )

    def execute(
        self, operation, vault, revision, access_token, key=None, *, identity=None
    ):
        if (
            operation not in ("enroll", "unlock", "revoke")
            or type(revision) is not int
            or revision < 0
        ):
            raise ValueError("Invalid vault key operation")
        if (
            not isinstance(vault, str)
            or not 1 <= len(vault) <= 128
            or any(not (c.isascii() and (c.isalnum() or c in "_-")) for c in vault)
        ):
            raise ValueError("Invalid vault identity")
        data = {
            "client_id": self.profiles.client,
            "operation": operation,
            "vault": vault,
            "public_key": self.public,
            "revision": revision,
        }
        if operation == "enroll":
            raw = base64.urlsafe_b64decode(key)
            if len(raw) != 32:
                raise ValueError("Invalid vault key")
            data["key"] = encode(raw)
        elif key is not None:
            raise ValueError("Unexpected vault key")
        result = self.profiles.transport(
            "POST", "vault/execute", data, token=access_token
        )
        if not isinstance(result, dict) or not isinstance(result.get("result"), dict):
            raise ValueError("Invalid protected key response")
        receipt = result["result"]
        if operation != "unlock":
            expected = "enrolled" if operation == "enroll" else "revoked"
            if (
                receipt.get("state") != expected
                or type(receipt.get("revision")) is not int
                or not isinstance(receipt.get("envelope"), str)
            ):
                raise ValueError("Invalid protected key receipt")
            return receipt
        delivery, token = receipt.get("delivery"), result.get("delivery_token")
        if (
            not isinstance(delivery, dict)
            or not isinstance(token, str)
            or len(token) > 4096
            or delivery.get("scheme") != "X25519-HKDF-SHA256-AES256-GCM-v1"
        ):
            raise ValueError("Unsupported protected key response")
        if receipt.get("revision") != revision:
            raise ValueError("Vault key revision changed")
        if identity is not None:
            try:
                claims = json.loads(decode(token.split(".")[0]))
            except (ValueError, IndexError, TypeError):
                raise ValueError("Invalid delivery binding") from None
            expected = {
                "issuer": self.profiles.issuer,
                "subject": identity["subject"],
                "installation": identity["installation"],
                "vault": vault,
                "public_key": self.public,
                "operation": "unlock",
                "revision": revision,
                "aud": "kagnode-vault-key-service",
            }
            if any(claims.get(k) != v for k, v in expected.items()):
                raise ValueError("Invalid delivery binding")
        salt = hashlib.sha256(token.encode()).digest()
        peer = X25519PublicKey.from_public_bytes(decode(delivery.get("ephemeral_key")))
        shared = self.private.exchange(peer)
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"kagnode-vault-key-delivery/v1",
        ).derive(shared)
        nonce = decode(delivery.get("nonce"))
        if len(nonce) != 12:
            raise ValueError("Invalid delivery nonce")
        raw = AESGCM(derived).decrypt(nonce, decode(delivery.get("ciphertext")), salt)
        if len(raw) != 32:
            raise ValueError("Invalid vault key")
        return base64.urlsafe_b64encode(raw)
