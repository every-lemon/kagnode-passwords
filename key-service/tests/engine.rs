use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use kagnode_vault_keys::{
    Request, Store,
    grant::{self, Grant, Operation},
};
use ring::{aead, agreement, hkdf, rand::SystemRandom};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Barrier};
const NOW: i64 = 1_800_000_000;
fn keys() -> (Vec<u8>, Vec<u8>) {
    (vec![19; 32], vec![27; 32])
}
fn client() -> agreement::EphemeralPrivateKey {
    agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new()).unwrap()
}
fn proof(operation: Operation, revision: i64, public: &[u8], jti: u8) -> Grant {
    let key_digest =
        (operation == Operation::Enroll).then(|| hex::encode(Sha256::digest([0x42; 32])));
    Grant {
        aud: "kagnode-vault-key-service".into(),
        issuer: "https://nebulacoder.com".into(),
        subject: "subject-fixture".into(),
        installation: "https://vault.fixture.invalid".into(),
        vault: "vault-fixture".into(),
        public_key: B64.encode(public),
        operation,
        jti: hex::encode([jti; 32]),
        issued_at: NOW,
        expires_at: NOW + 60,
        auth_at: NOW - 20,
        revision,
        key_digest,
    }
}
fn request(grant: &Grant, key: Option<&[u8]>) -> Request {
    let mut grant = grant.clone();
    if grant.operation == Operation::Enroll {
        grant.key_digest = key.map(|k| hex::encode(Sha256::digest(k)));
    }
    Request {
        grant: grant::sign(&grant, &keys().1).unwrap(),
        key: key.map(|k| B64.encode(k)),
    }
}
#[test]
fn enrollment_binds_the_exact_key_and_uncertain_receipts_reconcile_without_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir.path().join("keys.sqlite"));
    let public = client().compute_public_key().unwrap();
    let g = proof(Operation::Enroll, 0, public.as_ref(), 30);
    let mut tampered = request(&g, Some(&[0x42; 32]));
    tampered.key = Some(B64.encode([0x99; 32]));
    assert!(store.execute(tampered, NOW).is_err());
    let original = store.execute(request(&g, Some(&[0x42; 32])), NOW).unwrap();
    let retry = store
        .execute(
            request(
                &proof(Operation::Enroll, 0, public.as_ref(), 31),
                Some(&[0x42; 32]),
            ),
            NOW,
        )
        .unwrap();
    assert_eq!(original, retry);
    assert!(
        store
            .execute(
                request(
                    &proof(Operation::Enroll, 0, public.as_ref(), 32),
                    Some(&[0x99; 32])
                ),
                NOW
            )
            .is_err()
    );
}
fn store(path: &std::path::Path) -> Store {
    let (a, b) = keys();
    Store::open(path, a, b, "https://nebulacoder.com".into()).unwrap()
}
struct Len;
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        32
    }
}
#[test]
fn enrollment_is_encrypted_and_delivery_is_bound_to_the_installation_and_grant() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.sqlite");
    let store = store(&path);
    let private = client();
    let public = private.compute_public_key().unwrap();
    let key = [0x42; 32];
    let enrolled = store
        .execute(
            request(&proof(Operation::Enroll, 0, public.as_ref(), 1), Some(&key)),
            NOW,
        )
        .unwrap();
    assert_eq!(enrolled["revision"], 1);
    let grant = proof(Operation::Unlock, 1, public.as_ref(), 2);
    let request = request(&grant, None);
    let token = request.grant.clone();
    let response = store.execute(request, NOW).unwrap();
    assert!(!response.to_string().contains(&B64.encode(key)));
    let delivered = &response["delivery"];
    let ephemeral = B64
        .decode(delivered["ephemeral_key"].as_str().unwrap())
        .unwrap();
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, ephemeral);
    let salt = Sha256::digest(token.as_bytes());
    let shared = agreement::agree_ephemeral(private, &peer, |shared| shared.to_vec()).unwrap();
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(&shared);
    let info = [b"kagnode-vault-key-delivery/v1".as_slice()];
    let mut delivery_key = [0; 32];
    prk.expand(&info, Len)
        .unwrap()
        .fill(&mut delivery_key)
        .unwrap();
    let nonce: [u8; 12] = B64
        .decode(delivered["nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut ciphertext = B64
        .decode(delivered["ciphertext"].as_str().unwrap())
        .unwrap();
    let engine =
        aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &delivery_key).unwrap());
    assert_eq!(
        engine
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(salt.as_slice()),
                &mut ciphertext
            )
            .unwrap(),
        key
    );
    let db = rusqlite::Connection::open(path).unwrap();
    let bytes: Vec<u8> = db
        .query_row("SELECT ciphertext FROM envelopes", [], |r| r.get(0))
        .unwrap();
    assert!(!bytes.windows(32).any(|w| w == key));
}
#[test]
fn grants_are_single_use_after_restart_and_revocation_blocks_new_unlocks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.sqlite");
    let public = client().compute_public_key().unwrap();
    let grant = proof(Operation::Enroll, 0, public.as_ref(), 3);
    {
        let store = store(&path);
        store
            .execute(request(&grant, Some(&[0x42; 32])), NOW)
            .unwrap();
    }
    let store = store(&path);
    assert!(
        store
            .execute(request(&grant, Some(&[0x42; 32])), NOW)
            .is_err()
    );
    store
        .execute(
            request(&proof(Operation::Revoke, 1, public.as_ref(), 4), None),
            NOW,
        )
        .unwrap();
    assert!(
        store
            .execute(
                request(&proof(Operation::Unlock, 1, public.as_ref(), 5), None),
                NOW
            )
            .is_err()
    );
    assert!(
        store
            .execute(
                request(
                    &proof(Operation::Enroll, 1, public.as_ref(), 6),
                    Some(&[0x43; 32])
                ),
                NOW
            )
            .is_err()
    );
    assert_eq!(
        store
            .execute(
                request(
                    &proof(Operation::Enroll, 1, public.as_ref(), 7),
                    Some(&[0x42; 32])
                ),
                NOW
            )
            .unwrap()["revision"],
        2
    );
}
#[test]
fn forged_expired_stale_future_audience_and_invalid_public_keys_are_rejected() {
    let public = client().compute_public_key().unwrap();
    let original = proof(Operation::Unlock, 1, public.as_ref(), 8);
    for variant in 0..7 {
        let mut g = original.clone();
        match variant {
            0 => g.expires_at = NOW,
            1 => g.auth_at = NOW - 301,
            2 => g.auth_at = NOW + 6,
            3 => g.expires_at = NOW + 61,
            4 => g.aud = "profile".into(),
            5 => g.public_key = B64.encode([0; 32]),
            _ => g.revision = -1,
        };
        assert!(grant::verify(&request(&g, None).grant, &keys().1, &g.issuer, NOW).is_err());
    }
    let token = grant::sign(&original, &[99; 32]).unwrap();
    assert!(grant::verify(&token, &keys().1, &original.issuer, NOW).is_err());
}
#[test]
fn changing_vault_subject_or_installation_cannot_release_another_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir.path().join("keys.sqlite"));
    let public = client().compute_public_key().unwrap();
    store
        .execute(
            request(
                &proof(Operation::Enroll, 0, public.as_ref(), 10),
                Some(&[0x42; 32]),
            ),
            NOW,
        )
        .unwrap();
    for variant in 0..3 {
        let mut g = proof(Operation::Unlock, 1, public.as_ref(), 11 + variant);
        match variant {
            0 => g.vault = "other-vault".into(),
            1 => g.subject = "other-subject".into(),
            _ => g.installation = "https://another.fixture.invalid".into(),
        };
        assert!(store.execute(request(&g, None), NOW).is_err());
    }
}
#[test]
fn concurrent_redeeming_has_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(store(&dir.path().join("keys.sqlite")));
    let public = client().compute_public_key().unwrap();
    store
        .execute(
            request(
                &proof(Operation::Enroll, 0, public.as_ref(), 20),
                Some(&[0x42; 32]),
            ),
            NOW,
        )
        .unwrap();
    let g = proof(Operation::Unlock, 1, public.as_ref(), 21);
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let store = store.clone();
            let g = g.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store.execute(request(&g, None), NOW).is_ok()
            })
        })
        .collect();
    assert_eq!(
        threads
            .into_iter()
            .filter_map(|t| t.join().ok())
            .filter(|v| *v)
            .count(),
        1
    );
}
