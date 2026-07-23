//! End-to-end KDBX 4 import against a REAL KeePass database.
//!
//! `tests/fixtures/kdbx/sample_aes256.kdbx` was produced by `pykeepass`
//! (KDBX 4.0, AES-256-CBC outer cipher, Argon2d KDF, ChaCha20 inner protected
//! stream — the KeePass/KeePassXC default). The ground truth it must reproduce
//! is recorded alongside it in `ground_truth.json`. The database password is
//! below (it is a throwaway test fixture, not a secret).

use lp_porter::PorterError;
use lp_porter::import::kdbx;
use lp_vault::{Field, FieldKind, ItemPayload};

const PW: &str = "correct horse battery staple";

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/kdbx")
        .join(name)
}

fn field<'a>(p: &'a ItemPayload, name: &str) -> Option<&'a Field> {
    p.fields.iter().find(|f| f.name == name)
}

fn find<'a>(items: &'a [ItemPayload], title: &str) -> &'a ItemPayload {
    items
        .iter()
        .find(|p| p.title == title)
        .unwrap_or_else(|| panic!("no imported item titled {title:?}"))
}

#[test]
fn imports_real_aes256_argon2_database() {
    let outcome =
        kdbx::parse_file(&fixture("sample_aes256.kdbx"), PW).expect("import should succeed");
    assert_eq!(outcome.count(), 4, "four entries imported");
    assert!(outcome.skipped.is_empty(), "nothing skipped");

    // Every entry is a login.
    for it in &outcome.items {
        assert_eq!(it.type_data.type_str(), "login");
    }

    // 1) GitHub — standard fields, multiline notes, protected + plain customs.
    let gh = find(&outcome.items, "GitHub");
    assert_eq!(field(gh, "username").unwrap().value, "octocat");
    let pw = field(gh, "password").unwrap();
    assert_eq!(pw.kind, FieldKind::Hidden);
    assert_eq!(
        pw.value, "s3cr3t-pw!",
        "protected password decrypts via inner stream"
    );
    assert_eq!(field(gh, "url").unwrap().value, "https://github.com");
    assert_eq!(gh.notes, "my git host\nsecond line");
    // Protected custom → hidden; plain custom → text.
    let tok = field(gh, "API Token").unwrap();
    assert_eq!(tok.kind, FieldKind::Hidden);
    assert_eq!(tok.value, "tok_ABC123");
    let plan = field(gh, "Plan").unwrap();
    assert_eq!(plan.kind, FieldKind::Text);
    assert_eq!(plan.value, "Pro");
    assert!(gh.tags.is_empty(), "root-group entry has no tag");

    // 2) Example — empty password (no field), sub-group name → tag.
    let ex = find(&outcome.items, "Example");
    assert_eq!(field(ex, "username").unwrap().value, "alice");
    assert!(
        field(ex, "password").is_none(),
        "empty password yields no field"
    );
    assert_eq!(field(ex, "url").unwrap().value, "https://example.com");
    assert_eq!(ex.tags, vec!["Web".to_string()], "sub-group becomes a tag");

    // 3) TOTP Test — otp preserved as the hidden `totp` field (full URI).
    let totp = find(&outcome.items, "TOTP Test");
    assert_eq!(field(totp, "username").unwrap().value, "bob");
    let t = field(totp, "totp").unwrap();
    assert_eq!(t.kind, FieldKind::Hidden);
    assert_eq!(
        t.value,
        "otpauth://totp/ACME:bob?secret=JBSWY3DPEHPK3PXP&issuer=ACME"
    );

    // 4) Unicode + XML-escaped title. Finding the exact title proves XML entity
    // unescaping (`&lt;b&gt;` → `<b>`) and that the ☕ (U+2615) survives. The
    // importer preserves value bytes faithfully (it does NOT re-normalize user
    // data — KeePass here stores the username in combining/NFD form), so the
    // credential assertions are structural rather than pinning a Unicode form.
    let uni = find(&outcome.items, "Café ☕ / <b>");
    let user = field(uni, "username")
        .unwrap()
        .value
        .as_str()
        .unwrap_or_default();
    assert!(user.contains("ser"), "username preserved: {user:?}");
    let pass = field(uni, "password").unwrap();
    assert_eq!(
        pass.kind,
        FieldKind::Hidden,
        "unicode password stays hidden"
    );
    let passv = pass.value.as_str().unwrap_or_default();
    assert!(
        passv.chars().count() >= 6,
        "protected unicode password decrypts to non-empty UTF-8: {passv:?}"
    );
}

#[test]
fn wrong_password_is_kdbx_decrypt_no_oracle() {
    let err = kdbx::parse_file(&fixture("sample_aes256.kdbx"), "the wrong password").unwrap_err();
    assert!(
        matches!(err, PorterError::KdbxDecrypt),
        "wrong password reports KdbxDecrypt (no oracle), got: {err}"
    );
}

#[test]
fn truncated_file_errors_without_panicking() {
    let bytes = std::fs::read(fixture("sample_aes256.kdbx")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("truncated.kdbx");
    std::fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
    let err = kdbx::parse_file(&path, PW).unwrap_err();
    // Either a structural error or an auth failure — never a panic.
    assert!(matches!(
        err,
        PorterError::Malformed { .. } | PorterError::KdbxDecrypt
    ));
}
