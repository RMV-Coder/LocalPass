//! KDF determinism and sensitivity (integration-level).
//!
//! The byte-exact fixed vector lives as a unit test inside `src/muk.rs` (it
//! needs crate-internal access to the raw MUK bytes). Here we assert the
//! observable properties: determinism, and that every input independently
//! affects the output. The real 64 MiB parameters are exercised only in an
//! `#[ignore]`d test to keep the normal suite fast (PRD hard constraint).

use lp_crypto::{KdfParams, SecretKey, derive_master_unlock_key};

/// Cheap, fixed Argon2id params (m = 64 KiB, t = 1, p = 1) with a fixed salt so
/// derivations are fully reproducible.
fn cheap_fixed_params() -> KdfParams {
    KdfParams::with_salt(64, 1, 1, *b"0123456789abcdef")
}

/// A Secret Key round-tripped through its display encoding — a single stable
/// instance within a test, and incidentally an extra exercise of the decoder.
fn fixed_secret_key() -> SecretKey {
    let sk = SecretKey::generate();
    let display = sk.to_display_string();
    SecretKey::from_display_string(&display).expect("display round-trip")
}

#[test]
fn muk_is_deterministic() {
    let params = cheap_fixed_params();
    let sk = fixed_secret_key();
    let m1 = derive_master_unlock_key(b"correct horse battery staple", &sk, &params).unwrap();
    let m2 = derive_master_unlock_key(b"correct horse battery staple", &sk, &params).unwrap();
    assert_eq!(m1, m2, "derivation must be deterministic in all inputs");
}

#[test]
fn different_secret_key_changes_muk() {
    let params = cheap_fixed_params();
    let sk1 = SecretKey::generate();
    let sk2 = SecretKey::generate();
    let m1 = derive_master_unlock_key(b"pw", &sk1, &params).unwrap();
    let m2 = derive_master_unlock_key(b"pw", &sk2, &params).unwrap();
    assert_ne!(m1, m2, "a different Secret Key must yield a different MUK");
}

#[test]
fn different_salt_changes_muk() {
    let sk = fixed_secret_key();
    let p1 = KdfParams::with_salt(64, 1, 1, [0u8; 16]);
    let p2 = KdfParams::with_salt(64, 1, 1, [1u8; 16]);
    let m1 = derive_master_unlock_key(b"pw", &sk, &p1).unwrap();
    let m2 = derive_master_unlock_key(b"pw", &sk, &p2).unwrap();
    assert_ne!(m1, m2, "a different salt must yield a different MUK");
}

#[test]
fn different_password_changes_muk() {
    let params = cheap_fixed_params();
    let sk = fixed_secret_key();
    let m1 = derive_master_unlock_key(b"password-a", &sk, &params).unwrap();
    let m2 = derive_master_unlock_key(b"password-b", &sk, &params).unwrap();
    assert_ne!(m1, m2);
}

#[test]
fn recommended_matches_prd_values() {
    let p = KdfParams::recommended();
    assert_eq!(p.m_cost_kib(), 64 * 1024, "64 MiB");
    assert_eq!(p.t_cost(), 3);
    assert_eq!(p.p_cost(), 4);
}

/// Real-parameter derivation (64 MiB / t=3 / p=4). Ignored by default so the
/// normal suite stays fast (PRD hard constraint). Run with `-- --ignored`.
#[test]
#[ignore = "uses 64 MiB recommended params; slow"]
fn muk_with_recommended_params_is_deterministic() {
    let params = KdfParams::with_salt(64 * 1024, 3, 4, [7u8; 16]);
    let sk = SecretKey::generate();
    let m1 = derive_master_unlock_key(b"pw", &sk, &params).unwrap();
    let m2 = derive_master_unlock_key(b"pw", &sk, &params).unwrap();
    assert_eq!(m1, m2);
}
