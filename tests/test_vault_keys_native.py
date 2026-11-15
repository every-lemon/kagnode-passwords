"""Actual Rust private-socket/Python cryptographic interoperability; fixtures only."""

import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import tempfile
from types import SimpleNamespace
import pytest
from cryptography.fernet import Fernet
from authentactor.vault_keys import VaultKeys, encode, wrap_emergency, unwrap_emergency

BINARY = os.environ.get("KAGNODE_VAULT_KEYS_BINARY", "")


@pytest.mark.skipif(
    not BINARY, reason="Explicit isolated Rust key-service build is required"
)
def test_rust_socket_enrollment_delivery_revocation_and_emergency_recovery(tmp_path):
    root = tmp_path / "native-key-service"
    root.mkdir(mode=0o700)
    wrap, authority = root / "wrap.key", root / "authority.key"
    authority_bytes = secrets.token_bytes(32)
    wrap.write_bytes(secrets.token_bytes(32))
    authority.write_bytes(authority_bytes)
    wrap.chmod(0o600)
    authority.chmod(0o600)
    runtime = tempfile.TemporaryDirectory(prefix="kv-", dir=tmp_path.parents[2])
    endpoint = Path(runtime.name) / "key.sock"
    process = subprocess.Popen(
        [
            BINARY,
            "--database",
            str(root / "keys.sqlite"),
            "--wrapping-key",
            str(wrap),
            "--authority-key",
            str(authority),
            "--socket",
            str(endpoint),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        umask=0o077,
    )
    try:
        for _ in range(100):
            if endpoint.exists():
                break
            assert process.poll() is None, "Isolated native key service did not start"
            time.sleep(0.02)
        assert endpoint.exists()

        def transport(method, path, data, token=None):
            assert method == "POST" and path == "vault/execute"
            now = int(time.time())
            grant = {
                "aud": "kagnode-vault-key-service",
                "issuer": "https://nebulacoder.com",
                "subject": "fixture-subject",
                "installation": "https://vault.fixture.invalid",
                "vault": data["vault"],
                "public_key": data["public_key"],
                "operation": data["operation"],
                "jti": secrets.token_hex(32),
                "issued_at": now,
                "expires_at": now + 60,
                "auth_at": now,
                "revision": data["revision"],
            }
            if data["operation"] == "enroll":
                grant["key_digest"] = hashlib.sha256(
                    base64.urlsafe_b64decode(data["key"] + "=")
                ).hexdigest()
            payload = json.dumps(grant, separators=(",", ":")).encode()
            signed = (
                encode(payload)
                + "."
                + encode(
                    hmac.digest(
                        authority_bytes, b"kagnode-vault-grant-v1\0" + payload, "sha256"
                    )
                )
            )
            conn = http.client.HTTPConnection("localhost", timeout=5)
            conn.sock = socket.socket(socket.AF_UNIX)
            conn.sock.connect(str(endpoint))
            try:
                conn.request(
                    "POST",
                    "/api/v1/execute",
                    body=json.dumps({"grant": signed, "key": data.get("key")}).encode(),
                    headers={"Content-Type": "application/json"},
                )
                response = conn.getresponse()
                result = json.loads(response.read())
                if response.status != 200:
                    raise ValueError("Protected key operation rejected")
                return {"result": result, "delivery_token": signed}
            finally:
                conn.close()

        client = VaultKeys(
            root / "installation",
            SimpleNamespace(client="kagnode-authenticator", transport=transport),
        )
        data_key, emergency = Fernet.generate_key(), Fernet.generate_key()
        receipt = client.execute(
            "enroll", "fixture-vault", 0, "fixture-access", data_key
        )
        assert receipt["revision"] == 1
        payload = Fernet(data_key).encrypt(b"fictional existing vault data")
        released = client.execute("unlock", "fixture-vault", 1, "fixture-access")
        assert Fernet(released).decrypt(payload) == b"fictional existing vault data"
        wrapped = wrap_emergency(data_key, emergency)
        client.execute("revoke", "fixture-vault", 1, "fixture-access")
        with pytest.raises(ValueError):
            client.execute("unlock", "fixture-vault", 1, "fixture-access")
        assert (
            Fernet(unwrap_emergency(emergency, wrapped)).decrypt(payload)
            == b"fictional existing vault data"
        )
        for path in root.glob("keys.sqlite*"):
            raw = path.read_bytes()
            assert data_key not in raw and base64.urlsafe_b64decode(data_key) not in raw
    finally:
        process.terminate()
        process.wait(timeout=5)
        runtime.cleanup()
