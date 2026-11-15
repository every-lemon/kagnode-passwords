import base64
import hashlib
from types import SimpleNamespace
import pytest
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from authentactor.vault_keys import (
    VaultKeys,
    wrap_emergency,
    unwrap_emergency,
    encode,
    decode,
)


def test_emergency_wrapping_retains_legacy_and_stable_data_key():
    old, new, vault = (
        Fernet.generate_key(),
        Fernet.generate_key(),
        Fernet.generate_key(),
    )
    assert unwrap_emergency(old) == old
    wrapped = wrap_emergency(vault, old)
    assert unwrap_emergency(old, wrapped) == vault
    rotated = wrap_emergency(unwrap_emergency(old, wrapped), new)
    assert unwrap_emergency(new, rotated) == vault
    with pytest.raises(InvalidToken):
        unwrap_emergency(old, rotated)


def test_installation_key_survives_restart_and_rejects_symlink(tmp_path):
    profiles = SimpleNamespace(client="kagnode-authenticator")
    a = VaultKeys(tmp_path / "keys", profiles)
    assert VaultKeys(tmp_path / "keys", profiles).public == a.public
    path = a.path
    raw = path.read_bytes()
    path.unlink()
    replacement = tmp_path / "replacement"
    replacement.write_bytes(raw)
    replacement.chmod(0o600)
    path.symlink_to(replacement)
    with pytest.raises(OSError):
        VaultKeys(tmp_path / "keys", profiles)


def test_delivery_is_bound_to_grant_and_installation(tmp_path):
    key = Fernet.generate_key()

    def issuer(method, endpoint, data, token=None):
        assert method == "POST" and endpoint == "vault/execute"
        ephemeral = X25519PrivateKey.generate()
        shared = ephemeral.exchange(
            X25519PublicKey.from_public_bytes(decode(data["public_key"]))
        )
        salt = hashlib.sha256("fictional-opaque-grant".encode()).digest()
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"kagnode-vault-key-delivery/v1",
        ).derive(shared)
        nonce = b"fixtureNonce"
        return {
            "delivery_token": "fictional-opaque-grant",
            "result": {
                "revision": 1,
                "delivery": {
                    "scheme": "X25519-HKDF-SHA256-AES256-GCM-v1",
                    "ephemeral_key": encode(
                        ephemeral.public_key().public_bytes(
                            serialization.Encoding.Raw, serialization.PublicFormat.Raw
                        )
                    ),
                    "nonce": encode(nonce),
                    "ciphertext": encode(
                        AESGCM(derived).encrypt(
                            nonce, base64.urlsafe_b64decode(key), salt
                        )
                    ),
                },
            },
        }

    profiles = SimpleNamespace(client="kagnode-authenticator", transport=issuer)
    client = VaultKeys(tmp_path / "keys", profiles)
    assert client.execute("unlock", "vault-fixture", 1, "fictional-access-token") == key
    with pytest.raises(ValueError):
        client.execute("unlock", "vault-fixture", 2, "fictional-access-token")
