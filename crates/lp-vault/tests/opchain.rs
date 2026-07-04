//! Op-log hash-chain integration tests (sync-protocol.md §5): chain verification
//! after mixed operations, corruption detection, seq gaplessness, and Lamport
//! monotonicity.

use lp_vault::payload::{ItemPayload, TypeData};
use lp_vault::{AccountStore, Error};
use rusqlite::{Connection, params};
use tempfile::TempDir;

const PW: &str = "correct horse battery staple";

fn vault_path(dir: &std::path::Path, vault_id: &lp_vault::VaultId) -> std::path::PathBuf {
    dir.join("vaults")
        .join(format!("{}.vault", vault_id.to_hyphenated()))
}

/// Author a mix of create/update/delete/restore ops and return the vault id,
/// the op count, and the Secret Key (so callers can re-unlock and re-verify).
fn author_mixed_ops(dir: &std::path::Path) -> (lp_vault::VaultId, usize, lp_crypto::SecretKey) {
    let (session, sk) = AccountStore::create(dir, PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    let mut op_count = 0;

    // 3 creates.
    let mut ids = Vec::new();
    for i in 0..3 {
        let id = vault
            .create_item(&ItemPayload::new(TypeData::Note {}, format!("note {i}")))
            .unwrap();
        ids.push(id);
        op_count += 1;
    }
    // 2 updates on the first item.
    for i in 0..2 {
        let mut p = vault.get_item(ids[0]).unwrap().payload;
        p.title = format!("note 0 edit {i}");
        vault.update_item(ids[0], &p).unwrap();
        op_count += 1;
    }
    // 1 restore of the first item back to v1.
    vault.restore_version(ids[0], 1).unwrap();
    op_count += 1;
    // 1 delete of the second item.
    vault.delete_item(ids[1], 1000).unwrap();
    op_count += 1;

    // The freshly authored chain must verify.
    vault.verify_local_chain().unwrap();
    (vault_id, op_count, sk)
}

#[test]
fn chain_verifies_after_mixed_operations() {
    let dir = TempDir::new().unwrap();
    let (vault_id, op_count, sk) = author_mixed_ops(dir.path());
    assert_eq!(op_count, 7);

    // Re-open in a fresh session (from disk) and re-verify the whole chain.
    let session = AccountStore::unlock(dir.path(), PW, &sk).unwrap();
    let vault = session.open_vault(vault_id).unwrap();
    vault.verify_local_chain().unwrap();
}

#[test]
fn seq_is_gapless_and_lamport_strictly_increases_per_device() {
    let dir = TempDir::new().unwrap();
    let (vault_id, op_count, _sk) = author_mixed_ops(dir.path());
    let vpath = vault_path(dir.path(), &vault_id);
    let conn = Connection::open(&vpath).unwrap();

    // Single device: seq is exactly 1..=op_count with no gaps.
    let mut stmt = conn
        .prepare("SELECT seq FROM ops WHERE device_id = (SELECT device_id FROM ops LIMIT 1) ORDER BY seq")
        .unwrap();
    let seqs: Vec<i64> = stmt
        .query_map([], |r| r.get::<_, i64>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert_eq!(seqs.len(), op_count);
    for (i, s) in seqs.iter().enumerate() {
        assert_eq!(*s, (i as i64) + 1, "seq must be gapless from 1");
    }

    // Lamport strictly increases in authoring order (per this single device).
    let mut stmt2 = conn
        .prepare("SELECT lamport FROM ops ORDER BY seq")
        .unwrap();
    let lamports: Vec<i64> = stmt2
        .query_map([], |r| r.get::<_, i64>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    for w in lamports.windows(2) {
        assert!(w[1] > w[0], "lamport must strictly increase: {w:?}");
    }
}

#[test]
fn corrupting_a_prev_hash_breaks_the_chain() {
    let dir = TempDir::new().unwrap();
    let (vault_id, _n, sk) = author_mixed_ops(dir.path());
    let vpath = vault_path(dir.path(), &vault_id);

    // Flip one byte of a prev_hash (a chain-critical field) on the 4th op, then
    // re-verify through a real session: the link no longer matches op 3's hash.
    {
        let conn = Connection::open(&vpath).unwrap();
        let mut prev: Vec<u8> = conn
            .query_row("SELECT prev_hash FROM ops WHERE seq = 4", [], |r| r.get(0))
            .unwrap();
        prev[0] ^= 0xFF;
        conn.execute("UPDATE ops SET prev_hash = ?1 WHERE seq = 4", params![prev])
            .unwrap();
    }

    let session = AccountStore::unlock(dir.path(), PW, &sk).unwrap();
    let vault = session.open_vault(vault_id).unwrap();
    let err = vault.verify_local_chain().unwrap_err();
    assert!(matches!(err, Error::ChainVerification(_)), "got {err:?}");
}

#[test]
fn end_to_end_corruption_is_detected_by_verifier() {
    // Full path: keep the SecretKey so we can unlock and run verify_local_chain
    // after corrupting a row.
    let dir = TempDir::new().unwrap();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    let vault = session.open_vault(vault_id).unwrap();

    let id = vault
        .create_item(&ItemPayload::new(TypeData::Note {}, "a"))
        .unwrap();
    let mut p = vault.get_item(id).unwrap().payload;
    p.title = "b".into();
    vault.update_item(id, &p).unwrap();
    p.title = "c".into();
    vault.update_item(id, &p).unwrap();
    // Healthy chain verifies.
    vault.verify_local_chain().unwrap();
    drop(vault);
    session.lock();

    // Corrupt a signed field (payload_env) of op seq=2 with raw SQL.
    let vpath = vault_path(dir.path(), &vault_id);
    {
        let conn = Connection::open(&vpath).unwrap();
        let mut env: Vec<u8> = conn
            .query_row("SELECT payload_env FROM ops WHERE seq = 2", [], |r| {
                r.get(0)
            })
            .unwrap();
        // Flip a byte inside the ciphertext region (after the 25-byte envelope
        // header) so the signature over fields 1..10 no longer matches.
        let idx = env.len() - 1;
        env[idx] ^= 0xFF;
        conn.execute(
            "UPDATE ops SET payload_env = ?1 WHERE seq = 2",
            params![env],
        )
        .unwrap();
    }

    // Re-unlock and verify → must fail with ChainVerification.
    let session2 = AccountStore::unlock(dir.path(), PW, &sk).unwrap();
    let vault2 = session2.open_vault(vault_id).unwrap();
    let err = vault2.verify_local_chain().unwrap_err();
    assert!(matches!(err, Error::ChainVerification(_)), "got {err:?}");
}
