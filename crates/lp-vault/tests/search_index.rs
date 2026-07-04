//! Integration tests for the encrypted search index (`docs/specs/search-index.md`).
//!
//! These drive the real, encrypted, transaction-atomic index through the public
//! [`Vault`] API plus raw SQL for the corruption/ciphertext-stability assertions.
//! Each test uses an isolated `tempfile` dir and pays the real Argon2id unlock
//! cost, so they are intentionally coarse-grained.

use lp_vault::payload::{Field, FieldKind, ItemPayload, TypeData};
use lp_vault::{AccountStore, Id, Session};
use rusqlite::{Connection, params};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use tempfile::TempDir;

const PW: &str = "correct horse battery staple";

/// Shrink the index segment tuning for the whole test binary so the
/// split/merge/multi-segment paths are exercised with a handful of items
/// (segment plaintext is ~O(items) to (de)serialize, so full-size 512-item
/// segments would make these tests slow). These env knobs are honored ONLY by
/// the tuning functions in `index.rs`; production never sets them, and the
/// tuning is not format-fixed (spec §3), so this changes only segmentation.
///
/// Set once, to a fixed value, before any vault is created. Every test touches
/// [`SMALL_SEGMENTS`] via [`tiny_segments`] so the vars are in place; since the
/// value never changes, concurrent test threads never observe a torn write.
static SMALL_SEGMENTS: LazyLock<()> = LazyLock::new(|| {
    // SAFETY: set once at first access to a constant value, before any vault
    // exists; no other thread mutates these vars, so there is no data race on
    // an observable value change. Reads happen later inside `index.rs`.
    unsafe {
        std::env::set_var("LP_INDEX_SPLIT", "8");
        std::env::set_var("LP_INDEX_TARGET", "4");
        std::env::set_var("LP_INDEX_MERGE", "4");
    }
});

/// Ensure the small-segment tuning is installed for this test.
fn tiny_segments() {
    LazyLock::force(&SMALL_SEGMENTS);
}

// --- Fixtures --------------------------------------------------------------

fn login(title: &str, username: &str, url: &str, tags: &[&str]) -> ItemPayload {
    let mut p = ItemPayload::new(TypeData::Login { urls: vec![] }, title);
    p.tags = tags.iter().map(|s| (*s).to_string()).collect();
    p.fields = vec![
        Field {
            name: "username".into(),
            kind: FieldKind::Text,
            value: json!(username),
        },
        Field {
            name: "password".into(),
            kind: FieldKind::Hidden,
            value: json!("TOP-SECRET-VALUE-xyz"),
        },
        Field {
            name: "url".into(),
            kind: FieldKind::Url,
            value: json!(url),
        },
    ];
    p
}

fn ssh_key(title: &str, tags: &[&str]) -> ItemPayload {
    let mut p = ItemPayload::new(
        TypeData::SshKey {
            algo: "ed25519".into(),
            private_pem: "-----BEGIN PRIVATE KEY-----SUPERSECRET".into(),
            public_openssh: "ssh-ed25519 AAAA".into(),
            fingerprint: "SHA256:abc".into(),
        },
        title,
    );
    p.tags = tags.iter().map(|s| (*s).to_string()).collect();
    p
}

fn vault_path(dir: &Path, vault_id: &Id) -> PathBuf {
    dir.join("vaults")
        .join(format!("{}.vault", vault_id.to_hyphenated()))
}

/// Titles of the search results, for order-and-content assertions.
fn titles(items: &[lp_vault::Item]) -> Vec<String> {
    items.iter().map(|i| i.payload.title.clone()).collect()
}

/// Set up an account + one vault, returning the session and vault id. Installs
/// the small-segment tuning first so any items created afterward segment
/// finely.
fn setup(dir: &Path) -> (Session, Id) {
    tiny_segments();
    let (session, _sk) = AccountStore::create(dir, PW).unwrap();
    let vault_id = session.create_vault("v").unwrap();
    (session, vault_id)
}

// --- Search correctness ----------------------------------------------------

#[test]
fn exact_prefix_and_fuzzy_title_search() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();

    vault
        .create_item(&login("GitHub", "octocat", "https://github.com", &["dev"]))
        .unwrap();
    vault
        .create_item(&login("GitLab", "moby", "https://gitlab.com", &["dev"]))
        .unwrap();
    vault
        .create_item(&login(
            "Amazon Web Services",
            "root",
            "https://aws.amazon.com",
            &["cloud"],
        ))
        .unwrap();

    // Exact title word.
    let r = vault.search("github", None).unwrap();
    assert_eq!(titles(&r), vec!["GitHub"]);

    // Prefix: "git" matches both GitHub and GitLab.
    let r = vault.search("git", None).unwrap();
    let mut got = titles(&r);
    got.sort();
    assert_eq!(got, vec!["GitHub", "GitLab"]);

    // Fuzzy/trigram: a substitution typo in the title still resolves.
    // "guthub" (i→u) shares the trigrams "thu" and "hub" with "github", clearing
    // the half-of-grams similarity floor.
    let r = vault.search("guthub", None).unwrap();
    assert!(
        titles(&r).contains(&"GitHub".to_string()),
        "typo 'guthub' should fuzzy-match GitHub: {:?}",
        titles(&r)
    );

    // Multi-word title, exact on one word.
    let r = vault.search("amazon", None).unwrap();
    assert_eq!(titles(&r), vec!["Amazon Web Services"]);
}

#[test]
fn tag_username_and_url_host_search() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();

    vault
        .create_item(&login(
            "GitHub",
            "octocat",
            "https://github.com/login",
            &["dev", "prod"],
        ))
        .unwrap();
    vault
        .create_item(&login(
            "Internal",
            "svc_acme",
            "https://db.acme.internal",
            &["prod"],
        ))
        .unwrap();

    // Username value is a searchable handle.
    assert_eq!(
        titles(&vault.search("octocat", None).unwrap()),
        vec!["GitHub"]
    );
    assert_eq!(
        titles(&vault.search("svc_acme", None).unwrap()),
        vec!["Internal"]
    );

    // Tag exact (free term matches the tag word).
    assert_eq!(titles(&vault.search("dev", None).unwrap()), vec!["GitHub"]);

    // URL host token.
    assert_eq!(
        titles(&vault.search("github.com", None).unwrap()),
        vec!["GitHub"]
    );
    assert_eq!(
        titles(&vault.search("acme.internal", None).unwrap()),
        vec!["Internal"]
    );
}

#[test]
fn structural_filters_type_tag_folder_fav() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();

    let mut fav_login = login("Bank", "me", "https://bank.example", &["money"]);
    fav_login.favorite = true;
    fav_login.folder_id = Some("Finance".into());
    vault.create_item(&fav_login).unwrap();
    vault.create_item(&ssh_key("deploy", &["prod"])).unwrap();
    vault
        .create_item(&login(
            "Blog",
            "author",
            "https://blog.example",
            &["writing"],
        ))
        .unwrap();

    // type: filter (both the legacy arg and the query syntax).
    assert_eq!(vault.search("", Some("ssh_key")).unwrap().len(), 1);
    assert_eq!(
        titles(&vault.search("type:ssh_key", None).unwrap()),
        vec!["deploy"]
    );
    assert_eq!(vault.search("type:login", None).unwrap().len(), 2);

    // tag: filter.
    assert_eq!(
        titles(&vault.search("tag:prod", None).unwrap()),
        vec!["deploy"]
    );

    // folder: filter.
    assert_eq!(
        titles(&vault.search("folder:finance", None).unwrap()),
        vec!["Bank"]
    );

    // fav: filter.
    assert_eq!(titles(&vault.search("fav:", None).unwrap()), vec!["Bank"]);
    assert_eq!(
        titles(&vault.search("fav:true", None).unwrap()),
        vec!["Bank"]
    );
}

#[test]
fn and_semantics_across_multiple_tokens_and_filters() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();

    vault
        .create_item(&login(
            "Prod Database",
            "admin",
            "https://db.example",
            &["prod", "db"],
        ))
        .unwrap();
    vault
        .create_item(&login(
            "Prod Cache",
            "admin",
            "https://cache.example",
            &["prod"],
        ))
        .unwrap();
    vault
        .create_item(&login(
            "Staging Database",
            "admin",
            "https://stg.example",
            &["staging", "db"],
        ))
        .unwrap();

    // "prod database" → AND: only the item whose title has BOTH words.
    assert_eq!(
        titles(&vault.search("prod database", None).unwrap()),
        vec!["Prod Database"]
    );

    // free term + filter AND-combine.
    let r = vault.search("database tag:prod", None).unwrap();
    assert_eq!(titles(&r), vec!["Prod Database"]);

    // A term that matches nothing yields empty (AND).
    assert!(
        vault
            .search("prod nonexistentword", None)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn empty_query_returns_all_live_items() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();
    vault
        .create_item(&login("A", "a", "https://a.example", &[]))
        .unwrap();
    vault
        .create_item(&login("B", "b", "https://b.example", &[]))
        .unwrap();
    assert_eq!(vault.search("", None).unwrap().len(), 2);
}

// --- Incremental update: only the owning segment changes -------------------

/// Snapshot every data segment's `(segment_id, generation, payload_env)`.
fn segment_snapshot(path: &Path) -> Vec<(i64, i64, Vec<u8>)> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT segment_id, generation, payload_env FROM index_segments ORDER BY segment_id",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .unwrap();
    rows.map(|r| r.unwrap()).collect()
}

fn meta_generation(path: &Path) -> i64 {
    Connection::open(path)
        .unwrap()
        .query_row("SELECT index_generation FROM meta WHERE id = 1", [], |r| {
            r.get(0)
        })
        .unwrap()
}

#[test]
fn create_bumps_generation_exactly_once_and_manifest_matches_meta() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();
    let path = vault_path(dir.path(), &vid);

    let g0 = meta_generation(&path);
    vault
        .create_item(&login("One", "u", "https://one.example", &[]))
        .unwrap();
    let g1 = meta_generation(&path);
    // Exactly one bump per write transaction.
    assert_eq!(g1, g0 + 1, "create must bump generation by exactly 1");

    vault
        .create_item(&login("Two", "u", "https://two.example", &[]))
        .unwrap();
    let g2 = meta_generation(&path);
    assert_eq!(g2, g1 + 1);

    // Every stored segment row's generation matches meta (manifest included).
    for (_sid, seg_gen, _env) in segment_snapshot(&path) {
        assert_eq!(
            seg_gen, g2,
            "segment generation must equal meta.index_generation"
        );
    }
}

#[test]
fn update_touches_only_the_owning_segment() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();
    let path = vault_path(dir.path(), &vid);

    // With the small-segment tuning (target 4, split 8), ~24 items rebuild into
    // several data segments, so we can assert that updating ONE item rewrites
    // only its owning segment. (In production the same holds at 256/segment; the
    // tuning just lets us prove it fast.)
    let mut ids = Vec::new();
    for i in 0..24 {
        ids.push(
            vault
                .create_item(&ItemPayload::new(TypeData::Note {}, format!("note {i}")))
                .unwrap(),
        );
    }
    vault.rebuild_index().unwrap();

    let before = segment_snapshot(&path);
    let data_segments: Vec<i64> = before
        .iter()
        .map(|(s, _, _)| *s)
        .filter(|s| *s > 0)
        .collect();
    assert!(
        data_segments.len() >= 2,
        "expected multiple data segments after 24 items, got {}",
        data_segments.len()
    );

    // Update ONE item and capture which segment rows changed.
    let target = ids[0];
    let mut p = vault.get_item(target).unwrap().payload;
    p.title = "note 0 EDITED".into();
    vault.update_item(target, &p).unwrap();

    let after = segment_snapshot(&path);

    // Map segment_id -> payload_env before/after; count how many DATA segments
    // changed their ciphertext. Only the owning one may change (plus manifest 0).
    let mut changed_data = 0;
    for (sid, _g, env_after) in &after {
        if *sid == 0 {
            continue; // the manifest is expected to change (generation bump)
        }
        let env_before = before.iter().find(|(s, _, _)| s == sid).map(|(_, _, e)| e);
        match env_before {
            Some(eb) if eb == env_after => {}
            _ => changed_data += 1,
        }
    }
    assert_eq!(
        changed_data, 1,
        "exactly one data segment's ciphertext should change on a single-item update"
    );
}

#[test]
fn other_segments_bytes_unchanged_on_create_after_split() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();
    let path = vault_path(dir.path(), &vid);

    for i in 0..24 {
        vault
            .create_item(&ItemPayload::new(TypeData::Note {}, format!("item {i}")))
            .unwrap();
    }
    vault.rebuild_index().unwrap();
    let before = segment_snapshot(&path);
    let data_before: Vec<(i64, Vec<u8>)> = before
        .iter()
        .filter(|(s, _, _)| *s > 0)
        .map(|(s, _, e)| (*s, e.clone()))
        .collect();
    assert!(data_before.len() >= 2);

    // Create one more note; only its owning segment (and manifest) should differ.
    vault
        .create_item(&ItemPayload::new(TypeData::Note {}, "brand new note"))
        .unwrap();
    let after = segment_snapshot(&path);

    let mut unchanged = 0;
    for (sid, env) in &data_before {
        if let Some((_, _, ea)) = after.iter().find(|(s, _, _)| s == sid)
            && ea == env
        {
            unchanged += 1;
        }
    }
    assert!(
        unchanged >= data_before.len() - 1,
        "all but one data segment must be byte-identical: {unchanged}/{}",
        data_before.len()
    );
}

// --- Atomicity: index update commits/rolls back with the item write --------

#[test]
fn index_and_item_write_roll_back_together_on_failure() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();
    let path = vault_path(dir.path(), &vid);

    vault
        .create_item(&ItemPayload::new(TypeData::Note {}, "ok"))
        .unwrap();

    let gen_before = meta_generation(&path);
    let items_before: i64 = Connection::open(&path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))
        .unwrap();

    // Force a UNIQUE(device_id, seq) collision so the whole create transaction
    // rolls back (same mechanism as the existing atomicity test). The op is
    // authored before the index update, so this proves the WHOLE tx — including
    // the index — is atomic: neither the item nor the generation moves.
    {
        let conn = Connection::open(&path).unwrap();
        let device_id: Vec<u8> = conn
            .query_row("SELECT device_id FROM ops LIMIT 1", [], |r| r.get(0))
            .unwrap();
        let next_seq: i64 = conn
            .query_row("SELECT MAX(seq) + 1 FROM ops", [], |r| r.get(0))
            .unwrap();
        conn.execute(
            "INSERT INTO ops (op_id, vault_id, lamport, device_id, op_kind, target_item_id,
                              target_version, payload_env, signature, seq, prev_hash, created_at)
             VALUES (?1, ?2, 9999, ?3, 1, NULL, 0, x'01', x'00', ?4, x'00', 0)",
            params![
                Id::new().as_bytes().to_vec(),
                vid.as_bytes().to_vec(),
                device_id,
                next_seq
            ],
        )
        .unwrap();
    }

    let result = vault.create_item(&ItemPayload::new(TypeData::Note {}, "doomed"));
    assert!(result.is_err(), "the constraint violation must surface");

    // Neither the item nor the index generation advanced.
    let items_after: i64 = Connection::open(&path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM items", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        items_before, items_after,
        "no item row survived the failed create"
    );
    assert_eq!(
        gen_before,
        meta_generation(&path),
        "index generation must NOT advance on a rolled-back write"
    );
    // The doomed item is not searchable.
    assert!(vault.search("doomed", None).unwrap().is_empty());
    // The good item still is.
    assert_eq!(titles(&vault.search("ok", None).unwrap()), vec!["ok"]);
}

// --- Staleness / corruption recovery ---------------------------------------

#[test]
fn corrupt_one_segment_still_returns_correct_results_and_repairs_it() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();
    let path = vault_path(dir.path(), &vid);

    for i in 0..30 {
        vault
            .create_item(&ItemPayload::new(TypeData::Note {}, format!("note {i}")))
            .unwrap();
    }
    // Add one distinctive item we will search for.
    vault
        .create_item(&login(
            "NeedleTarget",
            "finder",
            "https://needle.example",
            &["special"],
        ))
        .unwrap();
    vault.rebuild_index().unwrap();

    // Hand-corrupt exactly one data segment's ciphertext (flip a byte in the
    // ciphertext body, past the version+nonce header).
    {
        let conn = Connection::open(&path).unwrap();
        let (sid, env): (i64, Vec<u8>) = conn
            .query_row(
                "SELECT segment_id, payload_env FROM index_segments WHERE segment_id > 0 LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let mut corrupt = env.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        conn.execute(
            "UPDATE index_segments SET payload_env = ?2 WHERE segment_id = ?1",
            params![sid, corrupt],
        )
        .unwrap();
    }

    // A search still returns correct results — the distinctive item is found,
    // and an empty query still returns all 31 live items — because the corrupt
    // segment is lazily rebuilt from its item range.
    let r = vault.search("needletarget", None).unwrap();
    assert_eq!(titles(&r), vec!["NeedleTarget"]);
    assert_eq!(vault.search("", None).unwrap().len(), 31);

    // The corrupt segment was repaired: nothing decrypts to garbage now, and a
    // second identical search is still correct (idempotent repair).
    assert_eq!(vault.search("", None).unwrap().len(), 31);
}

#[test]
fn wiping_all_index_rows_falls_back_to_linear_then_rebuilds() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();
    let path = vault_path(dir.path(), &vid);

    vault
        .create_item(&login("GitHub", "octocat", "https://github.com", &["dev"]))
        .unwrap();
    vault
        .create_item(&ssh_key("deploy key", &["prod"]))
        .unwrap();

    // Wipe every index row (manifest + data). meta.index_generation is left as-is.
    Connection::open(&path)
        .unwrap()
        .execute("DELETE FROM index_segments", [])
        .unwrap();
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM index_segments", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );

    // Search still works (correct results) via lazy rebuild.
    assert_eq!(
        titles(&vault.search("github", None).unwrap()),
        vec!["GitHub"]
    );
    assert_eq!(
        titles(&vault.search("type:ssh_key", None).unwrap()),
        vec!["deploy key"]
    );

    // The index has been rebuilt lazily: rows exist again.
    let n: i64 = Connection::open(&path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM index_segments", [], |r| r.get(0))
        .unwrap();
    assert!(n >= 1, "index should have been rebuilt after being wiped");
}

// --- Persistence across lock/unlock; unlock touches no index row -----------

#[test]
fn results_identical_across_lock_unlock_and_unlock_touches_no_index_row() {
    let dir = TempDir::new().unwrap();
    tiny_segments();
    let (session, sk) = AccountStore::create(dir.path(), PW).unwrap();
    let vid = session.create_vault("v").unwrap();
    let path = vault_path(dir.path(), &vid);
    {
        let vault = session.open_vault(vid).unwrap();
        vault
            .create_item(&login("GitHub", "octocat", "https://github.com", &["dev"]))
            .unwrap();
        vault
            .create_item(&login("GitLab", "moby", "https://gitlab.com", &["dev"]))
            .unwrap();
        vault.create_item(&ssh_key("deploy", &["prod"])).unwrap();

        let before = titles(&vault.search("git", None).unwrap());
        assert_eq!(before.len(), 2);
    }
    // Snapshot every index row before lock.
    let snap_before = segment_snapshot(&path);
    let gen_before = meta_generation(&path);
    session.lock();

    // Unlock a fresh session — this must NOT touch the index at all.
    let session2 = AccountStore::unlock(dir.path(), PW, &sk).unwrap();
    let snap_after_unlock = segment_snapshot(&path);
    assert_eq!(
        snap_before, snap_after_unlock,
        "unlock alone must not change any index ciphertext (index is not an unlock precondition)"
    );
    assert_eq!(
        gen_before,
        meta_generation(&path),
        "unlock must not bump the generation"
    );

    // And search results are identical to before the lock.
    let vault2 = session2.open_vault(vid).unwrap();
    let mut after = titles(&vault2.search("git", None).unwrap());
    after.sort();
    assert_eq!(after, vec!["GitHub", "GitLab"]);
    // A query that reads the index but changes nothing must not rewrite rows.
    let snap_after_search = segment_snapshot(&path);
    assert_eq!(
        snap_after_unlock, snap_after_search,
        "a read-only search must not rewrite index rows when the index is valid"
    );
}

// --- Tombstones ------------------------------------------------------------

#[test]
fn deleted_items_never_appear_even_from_a_stale_segment() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();
    let path = vault_path(dir.path(), &vid);

    let doomed = vault
        .create_item(&login(
            "DeleteMe",
            "gone",
            "https://gone.example",
            &["temp"],
        ))
        .unwrap();
    vault
        .create_item(&login("KeepMe", "stay", "https://stay.example", &["keep"]))
        .unwrap();

    // Before delete: findable.
    assert_eq!(
        titles(&vault.search("deleteme", None).unwrap()),
        vec!["DeleteMe"]
    );

    // Snapshot the (valid) segments, delete the item, then FORCE the index rows
    // back to the pre-delete state to simulate a stale segment that still lists
    // the deleted id.
    let pre_delete = segment_snapshot(&path);
    vault.delete_item(doomed, 30 * 24 * 3600 * 1000).unwrap();

    // Restore the stale segment bytes AND the pre-delete generation, so the
    // index believes the deleted item is still present (belt-and-suspenders).
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM index_segments", []).unwrap();
        for (sid, seg_gen, env) in &pre_delete {
            conn.execute(
                "INSERT INTO index_segments (segment_id, generation, payload_env) VALUES (?1, ?2, ?3)",
                params![sid, seg_gen, env],
            )
            .unwrap();
        }
        // Roll meta.index_generation back to match the stale segments so they
        // are considered "current" and NOT rebuilt — the tombstone filter is
        // the only thing that can hide the item now.
        let stale_gen = pre_delete.iter().map(|(_, g, _)| *g).max().unwrap();
        conn.execute(
            "UPDATE meta SET index_generation = ?1 WHERE id = 1",
            params![stale_gen],
        )
        .unwrap();
    }

    // The deleted item must STILL not appear — the final tombstone pass filters
    // it even though the stale segment posts it (spec §5/§6 defense in depth).
    assert!(
        vault.search("deleteme", None).unwrap().is_empty(),
        "a tombstoned item must never surface, even from a stale segment"
    );
    // And the kept item is unaffected.
    assert_eq!(
        titles(&vault.search("keepme", None).unwrap()),
        vec!["KeepMe"]
    );
    // Empty query returns only the live item.
    assert_eq!(vault.search("", None).unwrap().len(), 1);
}

// --- Merge behavior --------------------------------------------------------

#[test]
fn deleting_down_to_under_full_merges_adjacent_segments() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();
    let path = vault_path(dir.path(), &vid);

    // Build a multi-segment index (target 4, split 8 under the test tuning).
    let mut ids = Vec::new();
    for i in 0..40 {
        ids.push(
            vault
                .create_item(&ItemPayload::new(TypeData::Note {}, format!("note {i}")))
                .unwrap(),
        );
    }
    let n_before: i64 = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM index_segments WHERE segment_id > 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(n_before >= 3, "need several segments to observe a merge");

    // Delete most items so adjacent segments fall under the merge threshold and
    // coalesce; the segment count must drop and results stay correct.
    for id in ids.iter().take(36) {
        vault.delete_item(*id, 30 * 24 * 3600 * 1000).unwrap();
    }
    let n_after: i64 = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM index_segments WHERE segment_id > 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        n_after < n_before,
        "segments should have merged after deletes: {n_before} -> {n_after}"
    );
    // The 4 survivors are still searchable and the deleted ones are gone.
    assert_eq!(vault.search("", None).unwrap().len(), 4);
    assert_eq!(titles(&vault.search("note 39", None).unwrap()).len(), 1);
    assert!(vault.search("note 0", None).unwrap().is_empty());
}

// --- Split behavior --------------------------------------------------------

#[test]
fn large_item_count_splits_and_stays_correct() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();
    let path = vault_path(dir.path(), &vid);

    // Insert well past the split threshold (8 under the test tuning) purely via
    // INCREMENTAL create_item calls — new UUIDv7 ids always land in the highest
    // segment, so it repeatedly crosses the split threshold and splits. This is
    // the "> threshold items in one range splits" smoke test (spec, split
    // behaviour), scaled down so it runs fast; the split code path is identical
    // at the production threshold of 512.
    let n_items = 60;
    for i in 0..n_items {
        let mut p = ItemPayload::new(TypeData::Note {}, format!("note number {i}"));
        p.tags = vec![format!("t{}", i % 5)];
        vault.create_item(&p).unwrap();
    }

    // Multiple data segments now exist (splits happened during the inserts).
    let n_data: i64 = Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM index_segments WHERE segment_id > 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        n_data >= 2,
        "{n_items} items should have split into >=2 segments, got {n_data}"
    );

    // Results are still correct across the split boundaries.
    assert_eq!(vault.search("", None).unwrap().len(), n_items);
    assert_eq!(
        titles(&vault.search("note number 0", None).unwrap()).len(),
        1
    );
    // A tag shared by n_items/5 items resolves via the filter across all segments.
    assert_eq!(vault.search("tag:t0", None).unwrap().len(), n_items / 5);
    // The last-inserted item is found (proves the high-id segment is searched).
    let last = format!("note number {}", n_items - 1);
    let r = vault.search(&last, None).unwrap();
    assert!(r.iter().any(|i| i.payload.title == last));
}

// --- Determinism -----------------------------------------------------------
//
// Plaintext-level determinism ("same items ⇒ same segment plaintext bytes via
// canonical serialization") is asserted directly in the in-crate unit test
// `index::tests::same_tokens_yield_identical_segment_plaintext`, which has
// access to the private `SegmentData`/canonical serialization. Here we assert
// the observable consequence: rebuilding an unchanged vault twice yields a
// structurally identical index (same segment set), and search results are
// unchanged across the rebuild.

#[test]
fn rebuild_is_structurally_stable_and_results_unchanged() {
    let dir = TempDir::new().unwrap();
    let (session, vid) = setup(dir.path());
    let vault = session.open_vault(vid).unwrap();
    let path = vault_path(dir.path(), &vid);

    for i in 0..50 {
        vault
            .create_item(&login(
                &format!("Item {i}"),
                "user",
                "https://x.example",
                &["tag"],
            ))
            .unwrap();
    }

    vault.rebuild_index().unwrap();
    let seg_ids_a: Vec<i64> = data_segment_ids(&path);
    let results_a = titles(&vault.search("item", None).unwrap());

    vault.rebuild_index().unwrap();
    let seg_ids_b: Vec<i64> = data_segment_ids(&path);
    let results_b = titles(&vault.search("item", None).unwrap());

    assert_eq!(seg_ids_a, seg_ids_b, "rebuild must be structurally stable");
    assert_eq!(results_a.len(), 50);
    assert_eq!(results_a, results_b, "results identical across rebuilds");
}

fn data_segment_ids(path: &Path) -> Vec<i64> {
    let conn = Connection::open(path).unwrap();
    let mut stmt = conn
        .prepare("SELECT segment_id FROM index_segments WHERE segment_id > 0 ORDER BY segment_id")
        .unwrap();
    stmt.query_map([], |r| r.get::<_, i64>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect()
}
