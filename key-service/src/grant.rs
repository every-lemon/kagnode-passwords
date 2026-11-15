use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ring::hmac;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Enroll,
    Unlock,
    Revoke,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub aud: String,
    pub issuer: String,
    pub subject: String,
    pub installation: String,
    pub vault: String,
    pub public_key: String,
    pub operation: Operation,
    pub jti: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub auth_at: i64,
    pub revision: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_digest: Option<String>,
}
pub fn verify(token: &str, secret: &[u8], issuer: &str, now: i64) -> Result<Grant> {
    ensure!(token.len() <= 4096, "Invalid grant");
    let (payload, signature) = token
        .split_once('.')
        .ok_or_else(|| anyhow::anyhow!("Invalid grant"))?;
    let signature = B64.decode(signature)?;
    let bytes = B64.decode(payload)?;
    let mut message = b"kagnode-vault-grant-v1\0".to_vec();
    message.extend(&bytes);
    hmac::verify(
        &hmac::Key::new(hmac::HMAC_SHA256, secret),
        &message,
        &signature,
    )
    .map_err(|_| anyhow::anyhow!("Invalid grant"))?;
    let grant: Grant = serde_json::from_slice(&bytes)?;
    ensure!(
        grant.aud == "kagnode-vault-key-service" && grant.issuer == issuer,
        "Invalid grant audience"
    );
    ensure!(
        grant.issued_at > 0
            && grant.issued_at <= now.saturating_add(5)
            && grant.expires_at > now
            && grant.expires_at > grant.issued_at
            && grant.expires_at - grant.issued_at <= 60,
        "Expired grant"
    );
    ensure!(
        grant.auth_at > 0
            && grant.auth_at <= now.saturating_add(5)
            && now.saturating_sub(grant.auth_at) <= 300,
        "Recent authentication required"
    );
    ensure!(
        grant.jti.len() == 64 && grant.jti.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid grant identity"
    );
    for id in [&grant.subject, &grant.vault] {
        ensure!(
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "Invalid binding"
        );
    }
    ensure!(
        !grant.installation.is_empty()
            && grant.installation.len() <= 256
            && !grant.installation.chars().any(char::is_control),
        "Invalid installation"
    );
    ensure!(
        B64.decode(&grant.public_key)?.len() == 32,
        "Invalid installation key"
    );
    let private = ring::agreement::EphemeralPrivateKey::generate(
        &ring::agreement::X25519,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
    let peer = ring::agreement::UnparsedPublicKey::new(
        &ring::agreement::X25519,
        B64.decode(&grant.public_key)?,
    );
    ring::agreement::agree_ephemeral(private, &peer, |_| ())
        .map_err(|_| anyhow::anyhow!("Invalid installation key"))?;
    ensure!(grant.revision >= 0, "Invalid envelope revision");
    match grant.operation {
        Operation::Enroll => ensure!(
            grant.key_digest.as_ref().is_some_and(
                |value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
            ),
            "Enrollment must bind the data key"
        ),
        _ => ensure!(grant.key_digest.is_none(), "Unexpected enrollment binding"),
    }
    Ok(grant)
}
/// Used by issuer-side interoperability and isolated fixtures, never a public signing endpoint.
pub fn sign(grant: &Grant, secret: &[u8]) -> Result<String> {
    let bytes = serde_json::to_vec(grant)?;
    let mut message = b"kagnode-vault-grant-v1\0".to_vec();
    message.extend(&bytes);
    let signature = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, secret), &message);
    Ok(format!(
        "{}.{}",
        B64.encode(bytes),
        B64.encode(signature.as_ref())
    ))
}
