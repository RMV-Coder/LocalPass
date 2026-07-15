//! Full two-device flow with REAL profiles (no simulated signers): device A
//! shares a vault's key to device B through the sync channel's typed key
//! transport; B adopts it, pulls A's ops, reads the items, edits one, and A
//! pulls the edit back. This is the PRD §4.5 single-user multi-device story
//! end to end.
//!
//! Two `AccountStore::create` calls run the real Argon2id KDF (~1s each), so
//! everything lives in one test function.

use lp_sync::engine;
use lp_sync::store::FsStoreFactory;
use lp_vault::AccountStore;
use lp_vault::payload::{ItemPayload, TypeData};

fn login(title: &str, password: &str) -> ItemPayload {
    let mut p = ItemPayload::new(TypeData::Login { urls: vec![] }, title);
    p.fields.push(lp_vault::Field {
        name: "password".into(),
        kind: lp_vault::FieldKind::Hidden,
        value: password.into(),
    });
    p
}

#[test]
fn share_adopt_and_bidirectional_sync_between_real_devices() {
    // Device A: account + vault + an item.
    let dir_a = tempfile::tempdir().unwrap();
    let (session_a, _sk_a) = AccountStore::create(dir_a.path(), "pw-device-a").unwrap();
    let vault_id = session_a.create_vault("shared").unwrap();
    let item_id = {
        let vault_a = session_a.open_vault(vault_id).unwrap();
        vault_a.create_item(&login("GitHub", "hunter2")).unwrap()
    };

    // Device B: a separate account (its own AccountKey / SecretKey world).
    let dir_b = tempfile::tempdir().unwrap();
    let (session_b, _sk_b) = AccountStore::create(dir_b.path(), "pw-device-b").unwrap();

    // Mutual trust (the CLI's `device trust` with fingerprint confirmation
    // lands here; sync-protocol.md §6).
    let ident_a = session_a.device_public_identity();
    let ident_b = session_b.device_public_identity();
    session_a
        .trust_peer_device(
            &ident_b.device_id,
            &ident_b.ed25519_pub,
            &ident_b.x25519_pub,
            Some("device-b"),
        )
        .unwrap();
    session_b
        .trust_peer_device(
            &ident_a.device_id,
            &ident_a.ed25519_pub,
            &ident_a.x25519_pub,
            Some("device-a"),
        )
        .unwrap();

    // A enrolls + pushes, then seals the VaultKey to B via the channel.
    let root = tempfile::tempdir().unwrap();
    engine::setup(
        &session_a,
        vault_id,
        &root.path().to_string_lossy(),
        &FsStoreFactory,
    )
    .unwrap();
    {
        let vault_a = session_a.open_vault(vault_id).unwrap();
        engine::push(&session_a, &vault_a, &FsStoreFactory).unwrap();
    }
    engine::share_vault_to_device(&session_a, vault_id, &ident_b.device_id, &FsStoreFactory)
        .unwrap();

    // B adopts: the vault registers locally + enrolls, then a pull
    // materializes A's ops.
    let adopted =
        engine::adopt(&session_b, &root.path().to_string_lossy(), &FsStoreFactory).unwrap();
    assert_eq!(
        adopted,
        vec![vault_id],
        "B adopted exactly the shared vault"
    );
    let vault_b = session_b.open_vault(vault_id).unwrap();
    let report = engine::pull(&session_b, &vault_b, &FsStoreFactory).unwrap();
    assert!(!report.has_alarms());

    // B reads A's item, including the secret field.
    let got = vault_b.get_item(item_id).unwrap();
    assert_eq!(got.payload.title, "GitHub");
    assert_eq!(
        got.payload
            .fields
            .iter()
            .find(|f| f.name == "password")
            .unwrap()
            .value,
        "hunter2"
    );

    // The per-recipient blob was consumed; adopting again is a clean no-op.
    assert!(
        engine::adopt(&session_b, &root.path().to_string_lossy(), &FsStoreFactory)
            .unwrap()
            .is_empty()
    );

    // B edits and pushes; A pulls the edit back.
    vault_b
        .update_item(item_id, &login("GitHub", "rotated-9911"))
        .unwrap();
    engine::push(&session_b, &vault_b, &FsStoreFactory).unwrap();
    {
        let vault_a = session_a.open_vault(vault_id).unwrap();
        let back = engine::pull(&session_a, &vault_a, &FsStoreFactory).unwrap();
        assert_eq!(back.applied, 1, "A applied B's edit");
        assert!(!back.has_alarms());
        let seen = vault_a.get_item(item_id).unwrap();
        assert_eq!(
            seen.payload
                .fields
                .iter()
                .find(|f| f.name == "password")
                .unwrap()
                .value,
            "rotated-9911"
        );
        vault_a.verify_local_chain().unwrap();
    }
    vault_b.verify_local_chain().unwrap();
}

/// Adopting a vault whose name collides with one this device already has (both
/// "personal") disambiguates the incoming copy so name-based lookup stays
/// unambiguous — the bug a real two-device CLI round-trip surfaced.
#[test]
fn adopting_a_same_named_vault_is_disambiguated() {
    // Both devices have a "personal" vault (as the CLI/GUI create at init).
    let dir_a = tempfile::tempdir().unwrap();
    let (session_a, _sk_a) = AccountStore::create(dir_a.path(), "pw-a").unwrap();
    let personal_a = session_a.create_vault("personal").unwrap();

    let dir_b = tempfile::tempdir().unwrap();
    let (session_b, _sk_b) = AccountStore::create(dir_b.path(), "pw-b").unwrap();
    session_b.create_vault("personal").unwrap();

    // Mutual trust.
    let ident_a = session_a.device_public_identity();
    let ident_b = session_b.device_public_identity();
    session_a
        .trust_peer_device(
            &ident_b.device_id,
            &ident_b.ed25519_pub,
            &ident_b.x25519_pub,
            None,
        )
        .unwrap();
    session_b
        .trust_peer_device(
            &ident_a.device_id,
            &ident_a.ed25519_pub,
            &ident_a.x25519_pub,
            None,
        )
        .unwrap();

    // A shares its "personal" vault to B, who already has a "personal".
    let root = tempfile::tempdir().unwrap();
    engine::setup(
        &session_a,
        personal_a,
        &root.path().to_string_lossy(),
        &FsStoreFactory,
    )
    .unwrap();
    engine::share_vault_to_device(&session_a, personal_a, &ident_b.device_id, &FsStoreFactory)
        .unwrap();
    let adopted =
        engine::adopt(&session_b, &root.path().to_string_lossy(), &FsStoreFactory).unwrap();
    assert_eq!(adopted, vec![personal_a]);

    // B now has two distinct vault names: its own "personal" and the adopted
    // one, disambiguated to "personal (shared)".
    let names: Vec<String> = session_b
        .list_vaults()
        .unwrap()
        .into_iter()
        .map(|(_, n)| n)
        .collect();
    assert!(
        names.contains(&"personal".to_string()),
        "own default kept: {names:?}"
    );
    assert!(
        names.contains(&"personal (shared)".to_string()),
        "adopted vault disambiguated: {names:?}"
    );
    // The adopted vault opens by its now-unique name.
    assert!(
        session_b
            .list_vaults()
            .unwrap()
            .iter()
            .filter(|(_, n)| n == "personal")
            .count()
            == 1
    );
}
