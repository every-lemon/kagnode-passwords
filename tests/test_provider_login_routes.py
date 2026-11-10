"""A KagNode identity does not contain a vault key or bypass vault encryption."""

import json
import sqlite3

import pytest

from authentactor.server import create_app
from test_account_login import Issuer

PASSWORD = "Only a fictional vault password!"
HEADERS = {"X-Requested-With": "Authentactor"}


@pytest.fixture
def fixture(tmp_path):
    app = create_app(tmp_path / "vault")
    app.config["TESTING"] = True
    fake = Issuer(tmp_path / "issuer")
    links = app.extensions["kagnode_account"]
    links.transport = fake.call
    links.clock = lambda: fake.now
    # The helper owns the actual app client ID; our mocked proof must match it.
    fake.links.client = links.client
    app.extensions["kagnode_signins"].clock = lambda: fake.now
    return app, app.test_client(), fake


def confirm(client):
    status = client.get("/api/status").json
    headers = {**HEADERS, "X-CSRF-Token": status["csrf"]}
    started = client.post(
        "/api/kagnode-login", json={"action": "start"}, headers=headers
    )
    assert started.status_code == 200, started.json
    attempt = started.json["attempt_id"]
    result = client.post(
        "/api/kagnode-login",
        json={"action": "status", "attempt_id": attempt},
        headers=headers,
    )
    return headers, attempt, result


def test_new_provider_account_requires_explicit_master_password(fixture):
    app, client, fake = fixture
    headers, attempt, result = confirm(client)
    assert result.status_code == 200, result.json
    assert result.json["continuation"] == "setup"
    assert not client.get("/api/status").json["unlocked"]
    bad = client.post(
        "/api/setup",
        json={
            "provider_attempt": attempt,
            "email": "fictional@example.test",
            "password": "short",
        },
        headers=headers,
    )
    assert bad.status_code == 400
    good = client.post(
        "/api/setup",
        json={
            "provider_attempt": attempt,
            "email": "fictional@example.test",
            "password": PASSWORD,
        },
        headers=headers,
    )
    assert good.status_code == 200, good.json
    with sqlite3.connect(app.extensions["vault_testing"]["db_path"]) as db:
        payload = db.execute("SELECT payload FROM accounts").fetchone()[0]
        assert PASSWORD.encode() not in payload and b'"items"' not in payload
    assert client.get("/api/status").json["unlocked"]


def test_linked_provider_cannot_decrypt_or_switch_vault(fixture):
    app, client, fake = fixture
    created = client.post(
        "/api/setup",
        json={"email": "local@example.test", "password": PASSWORD},
        headers=HEADERS,
    )
    assert created.status_code == 200
    client.post(
        "/api/lock", json={}, headers={**HEADERS, "X-CSRF-Token": created.json["csrf"]}
    )
    with sqlite3.connect(app.extensions["vault_testing"]["db_path"]) as db:
        uid = db.execute("SELECT id FROM accounts").fetchone()[0]
    links = app.extensions["kagnode_account"]
    with links.db() as db:
        db.execute(
            "INSERT INTO links VALUES(?,?,?,?,?,0)",
            (
                uid,
                "subject-a",
                json.dumps(
                    {
                        "issuer": links.issuer,
                        "subject": "subject-a",
                        "name": "A",
                        "photo": "",
                    }
                ),
                "O" * 43,
                1000,
            ),
        )
    headers, attempt, result = confirm(client)
    assert (
        result.json["continuation"] == "unlock"
        and result.json["email"] == "local@example.test"
    )
    assert client.get("/api/items").status_code == 401
    assert (
        client.post(
            "/api/unlock",
            json={
                "email": "local@example.test",
                "password": "incorrect",
                "provider_attempt": attempt,
            },
            headers=headers,
        ).status_code
        == 401
    )
    response = client.post(
        "/api/unlock",
        json={
            "email": "local@example.test",
            "password": PASSWORD,
            "provider_attempt": attempt,
        },
        headers=headers,
    )
    assert response.status_code == 200


def test_same_email_is_not_automatic_account_link(fixture):
    app, client, _ = fixture
    created = client.post(
        "/api/setup",
        json={"email": "fictional@example.test", "password": PASSWORD},
        headers=HEADERS,
    )
    client.post(
        "/api/lock", json={}, headers={**HEADERS, "X-CSRF-Token": created.json["csrf"]}
    )
    _, _, result = confirm(client)
    assert result.status_code == 409 and "explicitly link" in result.json["error"]
    assert not client.get("/api/status").json["unlocked"]
    with app.extensions["kagnode_account"].db() as db:
        assert db.execute("SELECT COUNT(*) FROM links").fetchone()[0] == 0


def test_admin_disabled_keeps_local_vault_creation_usable(fixture):
    app, client, _ = fixture
    app.extensions["kagnode_account"].handle(
        "admin", "Admin", True, "policy", {"enabled": False}
    )
    status = client.get("/api/status").json
    assert status["provider_enabled"] is False
    headers = {**HEADERS, "X-CSRF-Token": status["csrf"]}
    assert (
        client.post(
            "/api/kagnode-login", json={"action": "start"}, headers=headers
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/setup",
            json={"email": "local@example.test", "password": PASSWORD},
            headers=HEADERS,
        ).status_code
        == 200
    )


def test_provider_endpoint_needs_csrf_and_same_origin(fixture):
    _, client, _ = fixture
    status = client.get("/api/status").json
    assert (
        client.post(
            "/api/kagnode-login", json={"action": "start"}, headers=HEADERS
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/kagnode-login",
            json={"action": "start"},
            headers={
                **HEADERS,
                "X-CSRF-Token": status["csrf"],
                "Origin": "https://evil.test",
            },
        ).status_code
        == 403
    )
