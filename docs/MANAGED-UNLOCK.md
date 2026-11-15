# KagNode-managed vault unlock

This optional mode trusts KagNode's key service to unlock an enrolled vault.
It is not a zero-knowledge service. The existing local master-password path stays
available for emergency access, outages and an installation's disabled connection.
Never reset an existing database to enable this feature.

## User flow

An unfamiliar KagNode identity chooses **Link existing account** or **Create
account**. Linking requires the existing vault email and password, even when the
verified KagNode email matches. Local roles are never granted by this connection.
Creation respects `KAGNODE_PASSWORDS_SIGNUP=0`.

After fresh KagNode consent, an existing vault is unlocked once with its current
password. The user explicitly enables managed unlock. Enrollment preserves its
encrypted items and adds an emergency key envelope. Later fresh KagNode sign-ins
can unlock this vault without asking for its master password again. Keep the
emergency password securely: KagNode account recovery does not reset it.

## Installation policy

`KAGNODE_PASSWORDS_MANAGED_UNLOCK=1` permits this installation to request the
separate `vault.unlock` scope. The issuer must advertise a configured service;
otherwise sign-in retains local unlock. The default is disabled. Existing profile
sync settings remain separate. Only enroll after reviewing the central trust model.

The private installation X25519 key is generated under
`<data-dir>/vault-key-installation/installation-x25519.key`, mode 0600. Back it up
securely with the installation. Once enrollment records exist, a missing key is
never silently replaced. Emergency password access still works; re-enrollment
with a replacement installation requires an explicit recovery procedure.

## Protocol and service

The Rust service lives in `key-service/`. Build with Rust 1.88 or later using
`cargo build --locked --release --manifest-path key-service/Cargo.toml`.
It listens only on a private Unix socket. The included systemd definition is an
example for an issuer host, not a service installed by normal source/data packages.
Use a dedicated service account and independent cryptographically random 32-byte
wrapping and grant-authority files, readable only by the required service identities.
The issuer reads the authority file and accesses the private socket; it never needs
the wrapping key. A browser never receives either secret.

The issuer requires active verified identity, browser-bound S256 consent, an
approved installation public key, `vault.unlock` and authentication within five
minutes. Grants bind issuer, subject, installation, vault, public key, operation,
revision and a random identity. They expire within 60 seconds and are redeemed
once, with replay tracking persisted in SQLite. Refresh does not renew the
authentication age. The issuer rechecks session revocation after native delivery.

Stored data keys use AES-256-GCM and binding metadata as authenticated data.
Delivery uses ephemeral X25519, HKDF-SHA256 and AES-256-GCM, bound to the full
grant. Installation keys, access tokens and data keys remain server-side; browser
URLs carry only single-use authorization codes, never vault keys or access tokens.
Root access to the issuer/key service remains trusted; no memory-erasure or
hardware-enclave immunity is claimed.

Enrollment uses an additive journal. A lost remote response leaves the local
record pending; a new fresh consent plus proof of the identical data key safely
reconciles it. An existing envelope cannot be overwritten with a different key.
Revocation prevents new unlocks; it cannot retract plaintext already disclosed.

## Backups, password changes and rollback

Local-only accounts keep version-1 encrypted backups. Enrolled accounts export
`kagnode-passwords-encrypted-v2`, containing ciphertext, KDF, salt and an encrypted
emergency data-key envelope. Both formats can be imported. Protect the file and
retain the emergency password current when it was created. The central key
service is unnecessary to decrypt an emergency backup.

Changing an enrolled account's master password rewraps its existing data key and
locks other local sessions. It does not rotate a data key previously disclosed to
a compromised server. Key compromise requires separate full re-encryption and
revocation, not merely changing a password.

The original legacy `vault` table is retained unchanged once an account enrolls.
Old binaries cannot consume the new wrapping metadata or subsequent changes.
Do not roll an enrolled database back to an old binary: use a consistent
pre-enrollment rollback backup, or recover through the current version's encrypted
backup import. Non-enrolled accounts retain the prior legacy mirror behavior.

## Verification

Tests exercise the real Rust private socket with Python and Node clients,
encrypted storage, fresh/replayed grants, installation/subject isolation,
concurrent redemption, revocation, interrupted enrollment, existing ciphertext,
emergency password changes, v2 backup import, outages and lost installation keys.
Native Bitwarden/Vaultwarden sign-in is a separate service and is not changed by
this web-vault protocol. No cross-client compatibility is implied.
