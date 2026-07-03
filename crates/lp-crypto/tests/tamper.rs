//! Tamper / negative-path matrix.
//!
//! Every mutation of every region of every wire format must fail, and must fail
//! as the single opaque [`lp_crypto::Error::DecryptionFailed`] (never a
//! distinguishing error) — except structural malformations, which are allowed
//! to surface as `MalformedEnvelope`.

use lp_crypto::{
    Envelope, Error, SealingKeyPair, SigningKeyPair, SymmetricKey, seal_for, unwrap_key, wrap_key,
};

/// Flip one bit in the byte at `idx`.
fn flip(bytes: &mut [u8], idx: usize) {
    bytes[idx] ^= 0x01;
}

fn assert_decryption_failed<T: core::fmt::Debug>(r: Result<T, Error>) {
    match r {
        Err(Error::DecryptionFailed) => {}
        other => panic!("expected DecryptionFailed, got {other:?}"),
    }
}

// --- Symmetric envelope tamper matrix ------------------------------------

#[test]
fn tamper_envelope_version_is_malformed() {
    let key = SymmetricKey::generate();
    let mut bytes = key.seal(b"data", b"aad").unwrap().to_bytes();
    // Corrupt the version byte (index 0).
    bytes[0] = 0x02;
    match Envelope::from_bytes(&bytes) {
        Err(Error::MalformedEnvelope(_)) => {}
        other => panic!("expected MalformedEnvelope, got {other:?}"),
    }
}

#[test]
fn tamper_envelope_nonce_fails_to_open() {
    let key = SymmetricKey::generate();
    let envelope = key.seal(b"data", b"aad").unwrap();
    let mut bytes = envelope.to_bytes();
    // Nonce occupies indices 1..25. Flip a bit inside it.
    flip(&mut bytes, 5);
    let tampered = Envelope::from_bytes(&bytes).unwrap();
    assert_decryption_failed(key.open(&tampered, b"aad"));
}

#[test]
fn tamper_envelope_ciphertext_fails_to_open() {
    let key = SymmetricKey::generate();
    let envelope = key.seal(b"some longer plaintext here", b"aad").unwrap();
    let mut bytes = envelope.to_bytes();
    // Ciphertext starts at index 25; flip a bit in the middle of it.
    let mid = 25 + (bytes.len() - 25) / 2;
    flip(&mut bytes, mid);
    let tampered = Envelope::from_bytes(&bytes).unwrap();
    assert_decryption_failed(key.open(&tampered, b"aad"));
}

#[test]
fn tamper_envelope_tag_fails_to_open() {
    let key = SymmetricKey::generate();
    let envelope = key.seal(b"data", b"aad").unwrap();
    let mut bytes = envelope.to_bytes();
    // The 16-byte tag is the final 16 bytes; flip a bit in the last byte.
    let last = bytes.len() - 1;
    flip(&mut bytes, last);
    let tampered = Envelope::from_bytes(&bytes).unwrap();
    assert_decryption_failed(key.open(&tampered, b"aad"));
}

#[test]
fn wrong_aad_fails_to_open() {
    let key = SymmetricKey::generate();
    let envelope = key.seal(b"data", b"correct-aad").unwrap();
    assert_decryption_failed(key.open(&envelope, b"wrong-aad"));
}

#[test]
fn wrong_key_fails_to_open() {
    let key = SymmetricKey::generate();
    let other = SymmetricKey::generate();
    let envelope = key.seal(b"data", b"aad").unwrap();
    assert_decryption_failed(other.open(&envelope, b"aad"));
}

// --- Envelope::from_bytes structural rejections --------------------------

#[test]
fn from_bytes_rejects_empty() {
    assert!(matches!(
        Envelope::from_bytes(&[]),
        Err(Error::MalformedEnvelope(_))
    ));
}

#[test]
fn from_bytes_rejects_truncated_nonce() {
    // version + 10 nonce bytes only.
    let bytes = [0x01u8; 11];
    assert!(matches!(
        Envelope::from_bytes(&bytes),
        Err(Error::MalformedEnvelope(_))
    ));
}

#[test]
fn from_bytes_rejects_ciphertext_shorter_than_tag() {
    // version(1) + nonce(24) + only 15 ciphertext bytes (< 16-byte tag).
    let bytes = [0x01u8; 1 + 24 + 15];
    assert!(matches!(
        Envelope::from_bytes(&bytes),
        Err(Error::MalformedEnvelope(_))
    ));
}

#[test]
fn from_bytes_rejects_wrong_version() {
    let mut bytes = vec![0x99u8];
    bytes.extend_from_slice(&[0u8; 24 + 16]);
    assert!(matches!(
        Envelope::from_bytes(&bytes),
        Err(Error::MalformedEnvelope(_))
    ));
}

// --- Key-wrap purpose binding --------------------------------------------

#[test]
fn unwrap_with_wrong_purpose_fails() {
    let wrapping = SymmetricKey::generate();
    let target = SymmetricKey::generate();

    // Wrapped as a vault-key; must NOT unwrap as an item-key.
    let wrapped = wrap_key(&wrapping, &target, "localpass/v1/wrap/vault-key").unwrap();
    assert_decryption_failed(unwrap_key(
        &wrapping,
        &wrapped,
        "localpass/v1/wrap/item-key",
    ));

    // Correct purpose still works.
    assert!(unwrap_key(&wrapping, &wrapped, "localpass/v1/wrap/vault-key").is_ok());
}

#[test]
fn wrap_rejects_purpose_outside_namespace() {
    let wrapping = SymmetricKey::generate();
    let target = SymmetricKey::generate();
    assert!(matches!(
        wrap_key(&wrapping, &target, "wrap/vault-key"),
        Err(Error::InvalidLabel(_))
    ));
}

// --- Asymmetric seal tamper matrix ---------------------------------------

#[test]
fn seal_for_wrong_recipient_fails() {
    let recipient = SealingKeyPair::generate();
    let wrong = SealingKeyPair::generate();
    let sealed = seal_for(&recipient.public_key(), b"secret", b"aad").unwrap();
    assert_decryption_failed(wrong.open(&sealed, b"aad"));
}

#[test]
fn seal_for_wrong_aad_fails() {
    let recipient = SealingKeyPair::generate();
    let sealed = seal_for(&recipient.public_key(), b"secret", b"aad").unwrap();
    assert_decryption_failed(recipient.open(&sealed, b"other-aad"));
}

#[test]
fn tamper_sealed_ephemeral_key_fails() {
    let recipient = SealingKeyPair::generate();
    let mut sealed = seal_for(&recipient.public_key(), b"secret", b"aad").unwrap();
    // Ephemeral pk occupies indices 1..33; flip a bit inside it.
    flip(&mut sealed, 10);
    assert_decryption_failed(recipient.open(&sealed, b"aad"));
}

#[test]
fn tamper_sealed_version_is_malformed() {
    let recipient = SealingKeyPair::generate();
    let mut sealed = seal_for(&recipient.public_key(), b"secret", b"aad").unwrap();
    sealed[0] = 0x02;
    match recipient.open(&sealed, b"aad") {
        Err(Error::MalformedEnvelope(_)) => {}
        other => panic!("expected MalformedEnvelope, got {other:?}"),
    }
}

#[test]
fn tamper_sealed_ciphertext_fails() {
    let recipient = SealingKeyPair::generate();
    let mut sealed = seal_for(&recipient.public_key(), b"a longer secret payload", b"aad").unwrap();
    // Inner envelope begins after 1 + 32 bytes; flip a byte deep in its ciphertext.
    let idx = sealed.len() - 20;
    flip(&mut sealed, idx);
    assert_decryption_failed(recipient.open(&sealed, b"aad"));
}

// --- Signature context / tamper matrix -----------------------------------

#[test]
fn verify_with_changed_context_fails() {
    let kp = SigningKeyPair::generate();
    let vk = kp.verifying_key();
    let sig = kp.sign("localpass/v1/sign/sync-op", b"msg").unwrap();

    // Same message, different context ⇒ must fail.
    assert_decryption_failed(vk.verify("localpass/v1/sign/membership", b"msg", &sig));
    // Correct context still verifies.
    assert!(vk.verify("localpass/v1/sign/sync-op", b"msg", &sig).is_ok());
}

#[test]
fn verify_with_tampered_message_fails() {
    let kp = SigningKeyPair::generate();
    let vk = kp.verifying_key();
    let sig = kp.sign("localpass/v1/sign/sync-op", b"original").unwrap();
    assert_decryption_failed(vk.verify("localpass/v1/sign/sync-op", b"tampered", &sig));
}

#[test]
fn verify_with_tampered_signature_fails() {
    let kp = SigningKeyPair::generate();
    let vk = kp.verifying_key();
    let mut sig = kp.sign("localpass/v1/sign/sync-op", b"msg").unwrap();
    flip(&mut sig, 0);
    assert_decryption_failed(vk.verify("localpass/v1/sign/sync-op", b"msg", &sig));
}

#[test]
fn verify_with_wrong_key_fails() {
    let kp = SigningKeyPair::generate();
    let other = SigningKeyPair::generate();
    let sig = kp.sign("localpass/v1/sign/sync-op", b"msg").unwrap();
    assert_decryption_failed(other.verifying_key().verify(
        "localpass/v1/sign/sync-op",
        b"msg",
        &sig,
    ));
}

#[test]
fn sign_rejects_context_outside_namespace() {
    let kp = SigningKeyPair::generate();
    assert!(matches!(
        kp.sign("sync-op", b"msg"),
        Err(Error::InvalidLabel(_))
    ));
}

// --- Length-prefix framing: no context/message ambiguity -----------------

#[test]
fn context_message_boundary_is_unambiguous() {
    // Without length-prefix framing, sign(ctx="ab", msg="cd") and
    // sign(ctx="abc", msg="d") could collide. Confirm they do not.
    let kp = SigningKeyPair::generate();
    let vk = kp.verifying_key();

    let sig = kp.sign("localpass/v1/ab", b"cd").unwrap();
    // A verify that shifts the boundary must fail.
    assert_decryption_failed(vk.verify("localpass/v1/abc", b"d", &sig));
    assert!(vk.verify("localpass/v1/ab", b"cd", &sig).is_ok());
}
