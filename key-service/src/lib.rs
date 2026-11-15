//! Trusted key service. It can decrypt enrolled keys; this is not zero-knowledge storage.
pub mod grant;
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use grant::{Grant, Operation};
use ring::{aead, agreement, hkdf, rand::SystemRandom};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Mutex};
use zeroize::Zeroizing;
pub struct Store {
    db: Mutex<Connection>,
    wrapping: Zeroizing<Vec<u8>>,
    authority: Zeroizing<Vec<u8>>,
    issuer: String,
}
#[derive(Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub grant: String,
    pub key: Option<String>,
}
#[derive(Serialize)]
struct Binding<'a> {
    issuer: &'a str,
    subject: &'a str,
    installation: &'a str,
    vault: &'a str,
    public_key: &'a str,
}
fn binding(g: &Grant) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&Binding {
        issuer: &g.issuer,
        subject: &g.subject,
        installation: &g.installation,
        vault: &g.vault,
        public_key: &g.public_key,
    })?)
}
fn random<const N: usize>() -> Result<[u8; N]> {
    let mut value = [0; N];
    getrandom::fill(&mut value).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
    Ok(value)
}
fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let nonce = random::<12>()?;
    let engine = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("Invalid key"))?,
    );
    let mut out = plaintext.to_vec();
    engine
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut out,
        )
        .map_err(|_| anyhow::anyhow!("Cannot protect key"))?;
    Ok((nonce.to_vec(), out))
}
fn unseal(
    key: &[u8],
    nonce: Vec<u8>,
    mut ciphertext: Zeroizing<Vec<u8>>,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid envelope"))?;
    let engine = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("Invalid key"))?,
    );
    let plain = engine
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| anyhow::anyhow!("Envelope integrity failure"))?;
    Ok(Zeroizing::new(plain.to_vec()))
}
struct KeyLength;
impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}
fn delivery(key: &[u8], public: &str, token: &str) -> Result<Value> {
    let rng = SystemRandom::new();
    let ephemeral = agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng)
        .map_err(|_| anyhow::anyhow!("Cannot create delivery key"))?;
    let public_ephemeral = ephemeral
        .compute_public_key()
        .map_err(|_| anyhow::anyhow!("Cannot create delivery key"))?;
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, B64.decode(public)?);
    let salt = Sha256::digest(token.as_bytes());
    let derived =
        agreement::agree_ephemeral(ephemeral, &peer, |shared| -> Result<Zeroizing<Vec<u8>>> {
            let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(shared);
            let info = [b"kagnode-vault-key-delivery/v1".as_slice()];
            let output = prk
                .expand(&info, KeyLength)
                .map_err(|_| anyhow::anyhow!("Cannot derive delivery key"))?;
            let mut key = Zeroizing::new(vec![0u8; 32]);
            output
                .fill(&mut key)
                .map_err(|_| anyhow::anyhow!("Cannot derive delivery key"))?;
            Ok(key)
        })
        .map_err(|_| anyhow::anyhow!("Invalid installation key"))??;
    let (nonce, cipher) = seal(&derived, key, &salt)?;
    Ok(
        json!({"ephemeral_key":B64.encode(public_ephemeral.as_ref()),"nonce":B64.encode(nonce),"ciphertext":B64.encode(cipher),"scheme":"X25519-HKDF-SHA256-AES256-GCM-v1"}),
    )
}
impl Store {
    pub fn open(
        path: &Path,
        wrapping: Vec<u8>,
        authority: Vec<u8>,
        issuer: String,
    ) -> Result<Self> {
        let origin: axum::http::Uri = issuer.parse()?;
        ensure!(
            origin.scheme_str() == Some("https")
                && origin
                    .authority()
                    .is_some_and(|a| !a.as_str().contains('@'))
                && origin.path_and_query().is_none_or(|p| p.as_str() == "/"),
            "Use an HTTPS issuer origin"
        );
        ensure!(path.is_absolute(), "Use an absolute database path");
        ensure!(
            wrapping.len() == 32 && authority.len() == 32 && wrapping != authority,
            "Use independent 32-byte keys"
        );
        let db = Connection::open(path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.pragma_update(None, "synchronous", "FULL")?;
        db.execute_batch("CREATE TABLE IF NOT EXISTS envelopes(id TEXT PRIMARY KEY,binding BLOB NOT NULL,nonce BLOB NOT NULL,ciphertext BLOB NOT NULL,revision INTEGER NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);CREATE TABLE IF NOT EXISTS spent(jti TEXT PRIMARY KEY,expires INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,envelope TEXT NOT NULL,action TEXT NOT NULL,created INTEGER NOT NULL);")?;
        Ok(Self {
            db: Mutex::new(db),
            wrapping: Zeroizing::new(wrapping),
            authority: Zeroizing::new(authority),
            issuer,
        })
    }
    pub fn execute(&self, request: Request, now: i64) -> Result<Value> {
        let grant = grant::verify(&request.grant, &self.authority, &self.issuer, now)?;
        let aad = binding(&grant)?;
        let id = hex::encode(Sha256::digest(&aad));
        let mut db = self
            .db
            .lock()
            .map_err(|_| anyhow::anyhow!("Service unavailable"))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute("DELETE FROM spent WHERE expires<?", [now])?;
        tx.execute(
            "INSERT INTO spent VALUES(?,?)",
            params![grant.jti, grant.expires_at],
        )
        .map_err(|_| anyhow::anyhow!("Grant already used"))?;
        let existing = tx
            .query_row(
                "SELECT nonce,ciphertext,revision,revoked FROM envelopes WHERE id=?",
                [&id],
                |r| {
                    Ok((
                        r.get::<_, Vec<u8>>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, bool>(3)?,
                    ))
                },
            )
            .optional()?;
        let result = match grant.operation {
            Operation::Enroll => {
                let plaintext = Zeroizing::new(B64.decode(request.key.as_deref().unwrap_or(""))?);
                ensure!(plaintext.len() == 32, "Invalid vault key");
                ensure!(
                    grant.key_digest.as_deref()
                        == Some(hex::encode(Sha256::digest(&plaintext)).as_str()),
                    "Enrollment key does not match the grant"
                );
                if let Some((nonce, cipher, revision, revoked)) = existing {
                    ensure!(
                        revision == grant.revision
                            || (!revoked && grant.revision == 0 && revision == 1),
                        "Envelope revision changed"
                    );
                    let prior = unseal(&self.wrapping, nonce, Zeroizing::new(cipher), &aad)?;
                    let comparison =
                        ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &random::<32>()?);
                    let tag = ring::hmac::sign(&comparison, &prior);
                    ensure!(
                        ring::hmac::verify(&comparison, &plaintext, tag.as_ref()).is_ok(),
                        "Existing envelope key cannot be overwritten"
                    );
                    if !revoked {
                        // A lost enrollment response may be reconciled only by a
                        // new fresh grant and proof of the identical data key.
                        tx.execute("INSERT INTO audit(envelope,action,created)VALUES(?,'enroll-reconciled',?)",params![id,now])?;
                        tx.commit()?;
                        return Ok(json!({"envelope":id,"revision":revision,"state":"enrolled"}));
                    }
                } else {
                    ensure!(grant.revision == 0, "Envelope revision changed");
                }
                let (nonce, cipher) = seal(&self.wrapping, &plaintext, &aad)?;
                let revision = grant
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("Revision exhausted"))?;
                tx.execute("INSERT INTO envelopes VALUES(?,?,?,?,?,0) ON CONFLICT(id) DO UPDATE SET nonce=excluded.nonce,ciphertext=excluded.ciphertext,revision=excluded.revision,revoked=0",params![id,aad,nonce,cipher,revision])?;
                json!({"envelope":id,"revision":revision,"state":"enrolled"})
            }
            Operation::Unlock => {
                ensure!(request.key.is_none(), "Unexpected key material");
                let (nonce, cipher, revision, revoked) =
                    existing.ok_or_else(|| anyhow::anyhow!("Envelope unavailable"))?;
                ensure!(
                    !revoked && revision == grant.revision,
                    "Envelope unavailable or changed"
                );
                let plaintext = unseal(&self.wrapping, nonce, Zeroizing::new(cipher), &aad)?;
                let encrypted = delivery(&plaintext, &grant.public_key, &request.grant)?;
                json!({"envelope":id,"revision":revision,"delivery":encrypted})
            }
            Operation::Revoke => {
                ensure!(request.key.is_none(), "Unexpected key material");
                let (_, _, revision, _) =
                    existing.ok_or_else(|| anyhow::anyhow!("Envelope unavailable"))?;
                ensure!(revision == grant.revision, "Envelope revision changed");
                tx.execute("UPDATE envelopes SET revoked=1 WHERE id=?", [&id])?;
                json!({"envelope":id,"revision":revision,"state":"revoked"})
            }
        };
        tx.execute(
            "INSERT INTO audit(envelope,action,created)VALUES(?,?,?)",
            params![id, serde_json::to_string(&grant.operation)?, now],
        )?;
        tx.commit()?;
        Ok(result)
    }
}
