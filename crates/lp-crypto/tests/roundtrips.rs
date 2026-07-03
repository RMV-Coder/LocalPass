//! Integration tests: happy-path round-trips across the whole public API.
//!
//! Tamper/negative cases live in `tamper.rs`; KDF vectors in `kdf_vectors.rs`.

use lp_crypto::{
    AccountKey, ItemKey, MasterUnlockKey, SealingKeyPair, SecretKey, SigningKeyPair, SymmetricKey,
    VaultKey, seal_for, unwrap_key, wrap_key,
};

#[test]
fn symmetric_seal_open_roundtrip() {
    let key = SymmetricKey::generate();
    let plaintext = b"the quick brown fox";
    let aad = b"item-id=42;version=7";

    let envelope = key.seal(plaintext, aad).unwrap();
    let opened = key.open(&envelope, aad).unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn seal_open_roundtrip_via_envelope_bytes() {
    let key = SymmetricKey::generate();
    let envelope = key.seal(b"payload", b"aad").unwrap();

    // Serialize and re-parse the envelope, then open.
    let bytes = envelope.to_bytes();
    let parsed = lp_crypto::Envelope::from_bytes(&bytes).unwrap();
    let opened = key.open(&parsed, b"aad").unwrap();
    assert_eq!(opened, b"payload");
}

#[test]
fn empty_plaintext_roundtrips() {
    let key = SymmetricKey::generate();
    let envelope = key.seal(b"", b"aad").unwrap();
    // Even empty plaintext produces at least a 16-byte tag.
    assert!(envelope.ciphertext().len() >= 16);
    assert_eq!(key.open(&envelope, b"aad").unwrap(), b"");
}

#[test]
fn derive_subkey_is_deterministic_and_label_separated() {
    let key = SymmetricKey::generate();
    let a1 = key.derive_subkey("localpass/v1/index").unwrap();
    let a2 = key.derive_subkey("localpass/v1/index").unwrap();
    let b = key.derive_subkey("localpass/v1/audit").unwrap();

    // Same label ⇒ same key (deterministic).
    assert_eq!(a1, a2);
    // Different label ⇒ different key.
    assert_ne!(a1, b);
}

#[test]
fn derive_subkey_rejects_labels_outside_namespace() {
    let key = SymmetricKey::generate();
    assert!(key.derive_subkey("index").is_err());
    assert!(key.derive_subkey("localpass/v2/index").is_err());
    assert!(key.derive_subkey("localpass/v1/").is_err());
    assert!(key.derive_subkey("localpass/v1/index").is_ok());
}

#[test]
fn wrap_unwrap_roundtrip_preserves_key() {
    // Wrap an AccountKey under a MUK-like key, then unwrap and confirm equality.
    let wrapping = SymmetricKey::generate();
    let target = SymmetricKey::generate();

    let wrapped = wrap_key(&wrapping, &target, "localpass/v1/wrap/account-key").unwrap();
    let unwrapped = unwrap_key(&wrapping, &wrapped, "localpass/v1/wrap/account-key").unwrap();

    assert_eq!(target, unwrapped);
}

#[test]
fn wrap_unwrap_through_role_keys() {
    // Exercise the role-key inner()/from_inner() path used by the vault layer:
    // wrap an AccountKey's core under a MUK's core, unwrap, and rebuild the role.
    let muk = MasterUnlockKey::generate();
    let account = AccountKey::generate();

    let wrapped = wrap_key(
        muk.inner(),
        account.inner(),
        "localpass/v1/wrap/account-key",
    )
    .unwrap();
    let recovered_core =
        unwrap_key(muk.inner(), &wrapped, "localpass/v1/wrap/account-key").unwrap();
    let recovered = AccountKey::from_inner(recovered_core);

    assert_eq!(account, recovered);
}

#[test]
fn full_hierarchy_wrap_chain() {
    // MUK → AccountKey → VaultKey → ItemKey, wrapping each under its parent,
    // then unwrapping the whole chain back down.
    let muk = MasterUnlockKey::generate();
    let account = AccountKey::generate();
    let vault = VaultKey::generate();
    let item = ItemKey::generate();

    let w_account = wrap_key(
        muk.inner(),
        account.inner(),
        "localpass/v1/wrap/account-key",
    )
    .unwrap();
    let w_vault = wrap_key(
        account.inner(),
        vault.inner(),
        "localpass/v1/wrap/vault-key",
    )
    .unwrap();
    let w_item = wrap_key(vault.inner(), item.inner(), "localpass/v1/wrap/item-key").unwrap();

    let account2 = AccountKey::from_inner(
        unwrap_key(muk.inner(), &w_account, "localpass/v1/wrap/account-key").unwrap(),
    );
    let vault2 = VaultKey::from_inner(
        unwrap_key(account2.inner(), &w_vault, "localpass/v1/wrap/vault-key").unwrap(),
    );
    let item2 = ItemKey::from_inner(
        unwrap_key(vault2.inner(), &w_item, "localpass/v1/wrap/item-key").unwrap(),
    );

    assert_eq!(item, item2);

    // And the item key actually decrypts a payload sealed under the original.
    let env = item.seal(b"secret value", b"aad").unwrap();
    assert_eq!(item2.open(&env, b"aad").unwrap(), b"secret value");
}

#[test]
fn seal_for_open_roundtrip() {
    let recipient = SealingKeyPair::generate();
    let plaintext = b"sealed to a recipient";
    let aad = b"context";

    let sealed = seal_for(&recipient.public_key(), plaintext, aad).unwrap();
    let opened = recipient.open(&sealed, aad).unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn seal_for_public_key_bytes_roundtrip() {
    let recipient = SealingKeyPair::generate();
    let pk_bytes = recipient.public_key().to_bytes();
    let pk = lp_crypto::PublicSealingKey::from_bytes(pk_bytes);

    let sealed = seal_for(&pk, b"hello", b"aad").unwrap();
    assert_eq!(recipient.open(&sealed, b"aad").unwrap(), b"hello");
}

#[test]
fn sign_verify_roundtrip() {
    let kp = SigningKeyPair::generate();
    let vk = kp.verifying_key();

    let sig = kp
        .sign("localpass/v1/sign/sync-op", b"operation bytes")
        .unwrap();
    assert!(
        vk.verify("localpass/v1/sign/sync-op", b"operation bytes", &sig)
            .is_ok()
    );
}

#[test]
fn verifying_key_bytes_roundtrip() {
    let kp = SigningKeyPair::generate();
    let vk_bytes = kp.verifying_key().to_bytes();
    let vk = lp_crypto::VerifyingKey::from_bytes(&vk_bytes).unwrap();

    let sig = kp.sign("localpass/v1/sign/release", b"v1.0.0").unwrap();
    assert!(
        vk.verify("localpass/v1/sign/release", b"v1.0.0", &sig)
            .is_ok()
    );
}

#[test]
fn secret_key_display_roundtrip() {
    let sk = SecretKey::generate();
    let display = sk.to_display_string();
    assert!(display.starts_with("LP1-"));

    let parsed = SecretKey::from_display_string(&display).unwrap();
    assert_eq!(sk, parsed);
}

#[test]
fn secret_key_display_is_case_and_dash_insensitive() {
    let sk = SecretKey::generate();
    let display = sk.to_display_string();

    // Lowercase and dash-stripped variants must still parse to the same key.
    let lower = display.to_lowercase();
    let no_dashes = display.replace('-', "");
    assert_eq!(SecretKey::from_display_string(&lower).unwrap(), sk);
    assert_eq!(SecretKey::from_display_string(&no_dashes).unwrap(), sk);
}
