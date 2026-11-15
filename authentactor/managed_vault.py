"""Additive vault enrollment journal; existing ciphertext and emergency access survive.

Remote enrollment precedes activation. An uncertain remote response stays pending
and can be reconciled after fresh authentication and proof of the same data key.
No plaintext password or data key is stored in this journal.
"""

import secrets
import sqlite3
from .vault_keys import wrap_emergency, unwrap_emergency


class ManagedVaults:
    def __init__(self, path):
        self.path = path
        with self.db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS managed_vaults(
              account_id TEXT PRIMARY KEY REFERENCES accounts(id),
              issuer TEXT NOT NULL,subject TEXT NOT NULL,installation TEXT NOT NULL,
              public_key TEXT NOT NULL,wrapped_key BLOB NOT NULL,
              revision INTEGER NOT NULL DEFAULT 0,envelope TEXT NOT NULL DEFAULT '',
              phase TEXT NOT NULL CHECK(phase IN ('pending','active','disabled')))
            """)

    def db(self):
        db = sqlite3.connect(self.path, timeout=20)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    def get(self, account):
        with self.db() as db:
            row = db.execute(
                "SELECT * FROM managed_vaults WHERE account_id=?", (account,)
            ).fetchone()
        return dict(row) if row else None

    def emergency(self, account, password_key):
        state = self.get(account)
        return unwrap_emergency(password_key, state["wrapped_key"] if state else None)

    def prepare(self, account, binding, key, password_key):
        wrapped = wrap_emergency(key, password_key)
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT * FROM managed_vaults WHERE account_id=?", (account,)
            ).fetchone()
            if old:
                if any(
                    old[k] != binding[k]
                    for k in ("issuer", "subject", "installation", "public_key")
                ):
                    raise ValueError(
                        "This vault has a different managed-unlock binding. Use emergency access and review its connection."
                    )
                if not secrets.compare_digest(
                    unwrap_emergency(password_key, old["wrapped_key"]), key
                ):
                    raise ValueError("The emergency key changed. Unlock again.")
            else:
                db.execute(
                    "INSERT INTO managed_vaults(account_id,issuer,subject,installation,public_key,wrapped_key,phase)VALUES(?,?,?,?,?,?,'pending')",
                    (
                        account,
                        binding["issuer"],
                        binding["subject"],
                        binding["installation"],
                        binding["public_key"],
                        wrapped,
                    ),
                )
        return self.get(account)

    def activate(self, account, previous, receipt):
        if (
            receipt.get("state") != "enrolled"
            or type(receipt.get("revision")) is not int
            or receipt["revision"] < 1
            or not isinstance(receipt.get("envelope"), str)
        ):
            raise ValueError("Invalid key-service enrollment receipt")
        with self.db() as db:
            changed = db.execute(
                "UPDATE managed_vaults SET phase='active',revision=?,envelope=? WHERE account_id=? AND revision=? AND public_key=? AND subject=?",
                (
                    receipt["revision"],
                    receipt["envelope"],
                    account,
                    previous["revision"],
                    previous["public_key"],
                    previous["subject"],
                ),
            ).rowcount
            if changed != 1:
                raise ValueError("Enrollment changed. Sign in again.")
