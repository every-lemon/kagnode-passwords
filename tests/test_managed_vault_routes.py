"""Full browser-continuation and emergency flows against the actual Rust service."""

import base64
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import time
import pytest
from authentactor.server import create_app
from authentactor.vault_keys import encode
from test_account_login import Issuer
from test_provider_login_routes import confirm, HEADERS, PASSWORD

BINARY = os.environ.get("KAGNODE_VAULT_KEYS_BINARY", "")
pytestmark = pytest.mark.skipif(
    not BINARY, reason="Explicit isolated Rust service binary is required"
)


@pytest.fixture
def managed(tmp_path, monkeypatch):
    monkeypatch.setenv("KAGNODE_PASSWORDS_MANAGED_UNLOCK", "1")
    root = tmp_path / "native"
    root.mkdir(mode=0o700)
    authority = secrets.token_bytes(32)
    for name, value in (("authority", authority), ("wrap", secrets.token_bytes(32))):
        (root / name).write_bytes(value)
        (root / name).chmod(0o600)
    runtime = tempfile.TemporaryDirectory(prefix="kv-", dir=tmp_path.parents[2])
    endpoint = Path(runtime.name) / "key.sock"
    process = subprocess.Popen(
        [
            BINARY,
            "--database",
            str(root / "keys.sqlite"),
            "--wrapping-key",
            str(root / "wrap"),
            "--authority-key",
            str(root / "authority"),
            "--socket",
            str(endpoint),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        umask=0o077,
    )
    for _ in range(100):
        if endpoint.exists():
            break
        assert process.poll() is None
        time.sleep(0.02)
    assert endpoint.exists()

    class Authority(Issuer):
        unavailable = False
        ambiguous = False

        def authorized(self):
            result = super().authorized()
            if self.device.get("vault_public_key"):
                result["scope"] += " vault.unlock"
                result["authorization"]["auth_time"] = self.now - 10
            return result

        def call(self, method, path, data=None, token=None):
            if path == "vault/capabilities":
                return {"enabled": True}
            if path != "vault/execute":
                return super().call(method, path, data, token)
            if self.unavailable:
                raise ValueError("Isolated simulated outage")
            assert token == "A" * 43
            assert data["public_key"] == self.device["vault_public_key"]
            now = int(time.time())
            claims = {
                "aud": "kagnode-vault-key-service",
                "issuer": self.links.issuer,
                "subject": self.subject,
                "installation": self.device["installation"],
                "public_key": self.device["vault_public_key"],
                "operation": data["operation"],
                "vault": data["vault"],
                "revision": data["revision"],
                "auth_at": now,
                "issued_at": now,
                "expires_at": now + 60,
                "jti": secrets.token_hex(32),
            }
            if data["operation"] == "enroll":
                claims["key_digest"] = hashlib.sha256(
                    base64.urlsafe_b64decode(data["key"] + "=")
                ).hexdigest()
            raw = json.dumps(claims, separators=(",", ":")).encode()
            grant = (
                encode(raw)
                + "."
                + encode(
                    hmac.digest(authority, b"kagnode-vault-grant-v1\0" + raw, "sha256")
                )
            )
            connection = http.client.HTTPConnection("localhost", timeout=5)
            connection.sock = socket.socket(socket.AF_UNIX)
            connection.sock.connect(str(endpoint))
            try:
                connection.request(
                    "POST",
                    "/api/v1/execute",
                    body=json.dumps({"grant": grant, "key": data.get("key")}),
                    headers={"Content-Type": "application/json"},
                )
                response = connection.getresponse()
                result = json.loads(response.read())
                if response.status != 200:
                    raise ValueError("Native grant rejected")
                if self.ambiguous:
                    self.ambiguous = False
                    raise ValueError("Enrollment accepted; response lost")
                return {"result": result, "delivery_token": grant}
            finally:
                connection.close()

    directory = tmp_path / "vault"
    app = create_app(directory)
    app.config["TESTING"] = True
    fake = Authority(tmp_path / "issuer")
    links = app.extensions["kagnode_account"]
    fake.links.client = links.client
    links.transport = fake.call
    links.clock = lambda: fake.now
    app.extensions["kagnode_signins"].clock = lambda: fake.now
    try:
        yield app, app.test_client(), fake, directory
    finally:
        process.terminate()
        process.wait(timeout=5)
        runtime.cleanup()


def lock(client):
    status = client.get("/api/status").json
    response = client.post(
        "/api/lock", json={}, headers={**HEADERS, "X-CSRF-Token": status["csrf"]}
    )
    assert response.status_code == 200, response.json


def make_local(client):
    response = client.post(
        "/api/setup",
        json={"email": "local@example.test", "password": PASSWORD},
        headers=HEADERS,
    )
    assert response.status_code == 200, response.json
    return response.json


def link(client, attempt, headers, password=PASSWORD):
    return client.post(
        "/api/unlock",
        json={
            "email": "local@example.test",
            "password": password,
            "provider_attempt": attempt,
            "provider_intent": "link",
            "managed_unlock": True,
        },
        headers=headers,
    )


def test_existing_ciphertext_managed_login_password_change_backup_and_outage(managed):
    app, client, fake, _ = managed
    make_local(client)
    database = app.extensions["vault_testing"]["db_path"]
    with sqlite3.connect(database) as db:
        before = db.execute("SELECT salt,payload FROM accounts").fetchone()
    lock(client)
    headers, attempt, result = confirm(client)
    assert result.json["continuation"] == "choose" and result.json["managed_available"]
    assert link(client, attempt, headers, "incorrect").status_code == 401
    response = link(client, attempt, headers)
    assert response.status_code == 200, response.json
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT salt,payload FROM accounts").fetchone() == before
        assert db.execute("SELECT phase,revision FROM managed_vaults").fetchone() == (
            "active",
            1,
        )
    lock(client)
    _, _, result = confirm(client)
    assert result.status_code == 200 and result.json["continuation"] == "unlocked", (
        result.json
    )
    assert client.get("/api/items").status_code == 200
    new_password = "A changed emergency password for isolated tests!"
    changed = client.post(
        "/api/change-password",
        json={"current": PASSWORD, "password": new_password},
        headers={**HEADERS, "X-CSRF-Token": result.json["csrf"]},
    )
    assert changed.status_code == 200, changed.json
    backup = client.get("/api/backup").json
    assert backup["format"] == "kagnode-passwords-encrypted-v2"
    restored = client.post(
        "/api/restore",
        json={"backup": backup, "password": new_password},
        headers={**HEADERS, "X-CSRF-Token": changed.json["csrf"]},
    )
    assert restored.status_code == 200, restored.json
    lock(client)
    fake.unavailable = True
    _, _, unavailable = confirm(client)
    assert (
        unavailable.status_code == 503
        and not client.get("/api/status").json["unlocked"]
    )
    assert (
        client.post(
            "/api/unlock",
            json={"email": "local@example.test", "password": PASSWORD},
            headers=HEADERS,
        ).status_code
        == 401
    )
    emergency = client.post(
        "/api/unlock",
        json={"email": "local@example.test", "password": new_password},
        headers=HEADERS,
    )
    assert emergency.status_code == 200, emergency.json
    lock(client)
    fake.unavailable = False
    _, _, result = confirm(client)
    assert result.json["continuation"] == "unlocked"
    app.extensions["kagnode_account"].handle(
        "admin", "Admin", True, "policy", {"enabled": False}
    )
    assert client.get("/api/items").status_code == 401
    assert (
        client.post(
            "/api/unlock",
            json={"email": "local@example.test", "password": new_password},
            headers=HEADERS,
        ).status_code
        == 200
    )


def test_ambiguous_enrollment_reconciles_without_reset_and_missing_key_fails_closed(
    managed,
):
    app, client, fake, directory = managed
    make_local(client)
    lock(client)
    headers, attempt, _ = confirm(client)
    fake.ambiguous = True
    failed = link(client, attempt, headers)
    assert failed.status_code == 503
    database = app.extensions["vault_testing"]["db_path"]
    with sqlite3.connect(database) as db:
        assert db.execute("SELECT phase FROM managed_vaults").fetchone()[0] == "pending"
    headers, attempt, _ = confirm(client)
    assert link(client, attempt, headers).status_code == 200
    lock(client)
    _, _, result = confirm(client)
    assert result.json["continuation"] == "unlocked"
    lock(client)
    (directory / "vault-key-installation" / "installation-x25519.key").unlink()
    restarted = create_app(directory)
    restarted.config["TESTING"] = True
    restarted.extensions["kagnode_account"].transport = fake.call
    restarted.extensions["kagnode_account"].clock = lambda: fake.now
    restarted.extensions["kagnode_signins"].clock = lambda: fake.now
    new_client = restarted.test_client()
    _, _, result = confirm(new_client)
    assert (
        result.json["continuation"] == "unlock" and not result.json["managed_available"]
    )
    assert not (
        directory / "vault-key-installation" / "installation-x25519.key"
    ).exists()
    assert (
        new_client.post(
            "/api/unlock",
            json={"email": "local@example.test", "password": PASSWORD},
            headers=HEADERS,
        ).status_code
        == 200
    )
