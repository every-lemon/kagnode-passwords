"""Update summaries are local-account metadata, never vault content or admin access."""

import tempfile
import unittest
from unittest.mock import patch
from authentactor.server import create_app
from authentactor.account_sync import ProfileLinks

EVENT = {
    "available": True,
    "notice": {
        "id": "a" * 64,
        "version": "5.0.6",
        "title": "Interface updated",
        "items": ["Improved shared controls."],
    },
}


class NoticeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.app = create_app(self.temp.name)
        self.patch = patch(
            "authentactor.kagnode_core.manager_request", return_value=EVENT
        )
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def account(self, email):
        client = self.app.test_client()
        result = client.post(
            "/api/setup",
            json={"email": email, "password": "Disposable vault master password 802!"},
            headers={"X-Requested-With": "Authentactor"},
        )
        self.assertEqual(result.status_code, 200)
        return client, {
            "X-Requested-With": "Authentactor",
            "X-CSRF-Token": result.json["csrf"],
        }

    def test_locked_vault_cannot_read_or_dismiss(self):
        client = self.app.test_client()
        self.assertEqual(client.get("/api/v1/kagnode-core/whats-new").status_code, 401)
        self.assertEqual(
            client.post(
                "/api/v1/kagnode-core/whats-new/dismiss",
                json={"id": "a" * 64},
                headers={"X-Requested-With": "Authentactor"},
            ).status_code,
            401,
        )

    def test_dismissal_requires_csrf_and_is_account_scoped(self):
        owner, oh = self.account("owner@notice.test")
        member, mh = self.account("member@notice.test")
        url = "/api/v1/kagnode-core/whats-new"
        self.assertEqual(member.get(url).json, EVENT)
        self.assertEqual(
            member.post(url + "/dismiss", json={"id": "a" * 64}).status_code, 403
        )
        self.assertEqual(
            member.post(
                url + "/dismiss", json={"id": "b" * 64}, headers=mh
            ).status_code,
            400,
        )
        self.assertEqual(
            member.post(url + "/dismiss", json={"id": "a" * 64}, headers=mh).json,
            {"dismissed": True},
        )
        self.assertIsNone(member.get(url).json["notice"])
        self.assertEqual(owner.get(url).json, EVENT)
        self.assertEqual(member.get("/api/v1/kagnode-core/status").status_code, 403)
        self.assertEqual(
            owner.post(url + "/dismiss", json={"id": "a" * 64}, headers=oh).status_code,
            200,
        )

    def test_receipt_persists_and_replaces_only_current_notice(self):
        links = ProfileLinks(self.temp.name + "/receipts", "fixture")
        links.notice_dismiss("local-owner", "a" * 64)
        reopened = ProfileLinks(self.temp.name + "/receipts", "fixture")
        self.assertTrue(reopened.notice_is_dismissed("local-owner", "a" * 64))
        self.assertFalse(reopened.notice_is_dismissed("different-owner", "a" * 64))
        reopened.notice_dismiss("local-owner", "b" * 64)
        self.assertFalse(links.notice_is_dismissed("local-owner", "a" * 64))
        with links.db() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM core_notice_receipts").fetchone()[0], 1
            )

    def test_unavailable_helper_does_not_leak_privileged_error(self):
        client, _ = self.account("owner@notice.test")
        with patch(
            "authentactor.kagnode_core.manager_request",
            side_effect=OSError("/private/credential-path"),
        ):
            self.assertEqual(
                client.get("/api/v1/kagnode-core/whats-new").json,
                {"available": False, "notice": None},
            )


if __name__ == "__main__":
    unittest.main()
