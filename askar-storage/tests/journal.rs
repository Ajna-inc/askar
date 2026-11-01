#![cfg(feature = "sqlite")]

use std::future::Future;
use std::time::Duration;

use askar_storage::{
    backend::{
        journal::{self, Export, JournalChange},
        sqlite::{SqliteBackend, SqliteStoreOptions},
        Backend, BackendSession, ManageBackend,
    },
    entry::{EntryKind, EntryOperation, EntryTag, TagFilter},
    future::block_on,
    generate_raw_store_key, StoreKeyMethod,
};

const DEFAULT: &str = "default";

fn path(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("askar-journal-{tag}-{}.db", uuid::Uuid::new_v4()))
        .to_string_lossy()
        .into_owned()
}

async fn provision(path: &str, recreate: bool) -> SqliteBackend {
    let key = generate_raw_store_key(None).unwrap();
    SqliteStoreOptions::new(path)
        .unwrap()
        .provision_backend(
            StoreKeyMethod::RawKey,
            key.as_ref(),
            Some(DEFAULT.into()),
            recreate,
        )
        .await
        .unwrap()
}

/// Run `f` against a fresh store, then remove it.
fn with_store<F, Fut>(tag: &str, f: F)
where
    F: FnOnce(SqliteBackend, String) -> Fut,
    Fut: Future<Output = SqliteBackend>,
{
    let path = path(tag);
    block_on(async {
        let store = provision(&path, false).await;
        let store = f(store, path.clone()).await;
        store.close().await.unwrap();
        SqliteStoreOptions::new(path.as_str())
            .unwrap()
            .remove_backend()
            .await
            .unwrap();
    });
}

async fn write(
    store: &SqliteBackend,
    profile: &str,
    kind: EntryKind,
    op: EntryOperation,
    category: &str,
    name: &str,
    value: &[u8],
    tags: &[EntryTag],
    expiry_ms: Option<i64>,
) {
    let mut session = store.session(Some(profile.into()), true).unwrap();
    let value = (op != EntryOperation::Remove).then_some(value);
    let tags = (op != EntryOperation::Remove).then_some(tags);
    session
        .update(kind, op, category, name, value, tags, expiry_ms)
        .await
        .unwrap();
    session.close(true).await.unwrap();
}

async fn put(store: &SqliteBackend, profile: &str, category: &str, name: &str, value: &[u8]) {
    write(
        store,
        profile,
        EntryKind::Item,
        EntryOperation::Insert,
        category,
        name,
        value,
        &[],
        None,
    )
    .await
}

async fn seq(store: &SqliteBackend) -> u64 {
    store.journal_head().await.unwrap().expect("journal on").seq
}

fn tag(name: &str, value: &str) -> EntryTag {
    EntryTag::Encrypted(name.into(), value.into())
}

/// Two exports hold the same profiles and entries (kind, value, tags), and expiries within
/// `slack_ms` (an import re-expresses expiry relative to its own clock).
fn assert_exports_equal(a: &Export, b: &Export, slack_ms: i64) {
    let sorted = |e: &Export| {
        let mut profiles = e.profiles.clone();
        profiles.sort_by(|x, y| x.name.cmp(&y.name));
        for p in profiles.iter_mut() {
            p.entries.sort_by(|x, y| {
                (x.entry.kind as u8, &x.entry.category, &x.entry.name).cmp(&(
                    y.entry.kind as u8,
                    &y.entry.category,
                    &y.entry.name,
                ))
            });
        }
        profiles
    };
    let (a, b) = (sorted(a), sorted(b));
    assert_eq!(
        a.iter().map(|p| &p.name).collect::<Vec<_>>(),
        b.iter().map(|p| &p.name).collect::<Vec<_>>()
    );
    for (pa, pb) in a.iter().zip(b.iter()) {
        assert_eq!(pa.entries.len(), pb.entries.len(), "profile {}", pa.name);
        for (ea, eb) in pa.entries.iter().zip(pb.entries.iter()) {
            assert_eq!(ea.entry.kind, eb.entry.kind);
            assert_eq!(ea.entry, eb.entry);
            match (ea.expires_at_ms, eb.expires_at_ms) {
                (None, None) => (),
                (Some(x), Some(y)) => assert!((x - y).abs() <= slack_ms, "{x} vs {y}"),
                other => panic!("expiry differs: {other:?}"),
            }
        }
    }
}

/// Restore `source` into a fresh store from `base` plus every change after it, `page` journal
/// rows at a time, and return the restored store's export.
async fn restore(source: &SqliteBackend, base: &Export, page: usize) -> Export {
    let path = path("restore");
    let target = provision(&path, false).await;
    journal::import(&target, base).await.unwrap();
    let mut after = base.head.expect("base has a journal head").seq;
    loop {
        let changes = source.journal_changes(after, page).await.unwrap();
        assert!(!changes.rebase_needed);
        journal::apply_changes(&target, &changes).await.unwrap();
        after = changes.through;
        if !changes.more {
            break;
        }
    }
    let out = target.export().await.unwrap();
    target.close().await.unwrap();
    SqliteStoreOptions::new(path.as_str())
        .unwrap()
        .remove_backend()
        .await
        .unwrap();
    out
}

#[test]
fn every_write_path_is_journaled_once() {
    with_store("paths", |store, _| async move {
        let mut at = store.enable_journal().await.unwrap().seq;
        assert_eq!(at, 0);
        let mut step = |n: u64, now: u64, what: &str| {
            assert_eq!(now, at + n, "{what}");
            at = now;
        };

        put(&store, DEFAULT, "c", "a", b"1").await;
        step(1, seq(&store).await, "insert");

        write(
            &store,
            DEFAULT,
            EntryKind::Item,
            EntryOperation::Replace,
            "c",
            "a",
            b"2",
            &[],
            None,
        )
        .await;
        step(1, seq(&store).await, "replace value");

        let tags = [tag("t", "v")];
        write(
            &store,
            DEFAULT,
            EntryKind::Item,
            EntryOperation::Replace,
            "c",
            "a",
            b"2",
            &tags,
            None,
        )
        .await;
        step(1, seq(&store).await, "replace tags only");

        write(
            &store,
            DEFAULT,
            EntryKind::Item,
            EntryOperation::Remove,
            "c",
            "a",
            b"",
            &[],
            None,
        )
        .await;
        step(1, seq(&store).await, "remove");

        for name in ["x", "y", "z"] {
            put(&store, DEFAULT, "many", name, b"v").await;
        }
        step(3, seq(&store).await, "three inserts");
        let mut session = store.session(None, true).unwrap();
        let removed = session
            .remove_all(Some(EntryKind::Item), Some("many"), None::<TagFilter>)
            .await
            .unwrap();
        session.close(true).await.unwrap();
        assert_eq!(removed, 3);
        step(3, seq(&store).await, "remove_all by category");

        write(
            &store,
            DEFAULT,
            EntryKind::Kms,
            EntryOperation::Insert,
            "key",
            "k1",
            b"secret",
            &[],
            None,
        )
        .await;
        step(1, seq(&store).await, "key insert");

        store.create_profile(Some("other".into())).await.unwrap();
        put(&store, "other", "c", "o", b"1").await;
        step(1, seq(&store).await, "insert in second profile");
        assert!(store.remove_profile("other".into()).await.unwrap());
        step(1, seq(&store).await, "profile removal cascades");

        let changes = store.journal_changes(0, 1000).await.unwrap();
        assert!(!changes.more && !changes.rebase_needed);
        assert_eq!(changes.through, at);
        assert_eq!(changes.profiles, vec![DEFAULT.to_string()]);
        // One change per item still in a live profile: a, x, y, z removed; k1 present.
        assert_eq!(changes.changes.len(), 5);
        assert!(changes.changes.iter().any(|c| matches!(c,
            JournalChange::Upsert { entry, .. }
                if entry.entry.kind == EntryKind::Kms && entry.entry.name == "k1")));
        assert!(changes.changes.iter().any(|c| matches!(c,
            JournalChange::Delete { name, category, .. } if name == "a" && category == "c")));
        store
    });
}

#[test]
fn a_rolled_back_transaction_records_nothing() {
    with_store("rollback", |store, _| async move {
        store.enable_journal().await.unwrap();
        let mut session = store.session(None, true).unwrap();
        session
            .update(
                EntryKind::Item,
                EntryOperation::Insert,
                "c",
                "a",
                Some(b"1"),
                None,
                None,
            )
            .await
            .unwrap();
        session.close(false).await.unwrap();
        assert_eq!(seq(&store).await, 0);
        store
    });
}

#[test]
fn writes_from_code_without_the_journal_are_recorded() {
    with_store("legacy", |store, path| async move {
        store.enable_journal().await.unwrap();
        // Another program, writing the file with plain SQL.
        let pool = sqlx::SqlitePool::connect(&format!("sqlite://{path}"))
            .await
            .unwrap();
        let version: String = sqlx::query_scalar("SELECT value FROM config WHERE name='version'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(version, "1", "the store version is unchanged");
        sqlx::query(
            "INSERT INTO items (profile_id, kind, category, name, value)
            VALUES (1, 2, x'00', x'01', x'02')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("DELETE FROM items WHERE name = x'01'")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
        assert_eq!(seq(&store).await, 2);
        store
    });
}

#[test]
fn export_then_changes_restore_an_equal_store() {
    with_store("roundtrip", |store, _| async move {
        store.enable_journal().await.unwrap();
        store.create_profile(Some("p2".into())).await.unwrap();
        for i in 0..20 {
            put(
                &store,
                DEFAULT,
                "seed",
                &format!("s{i}"),
                format!("v{i}").as_bytes(),
            )
            .await;
        }
        let base = store.export().await.unwrap();

        // A deterministic mix of writes across two profiles, with tags and expiry.
        let mut x: u32 = 0x9E37_79B9;
        let mut rand = move |n: u32| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x % n
        };
        for i in 0..300 {
            let profile = if rand(2) == 0 { DEFAULT } else { "p2" };
            let name = format!("n{}", rand(40));
            let value = format!("v{i}");
            let tags = [tag("t", &format!("{}", rand(5)))];
            let expiry = (rand(4) == 0).then_some(3_600_000);
            let mut session = store.session(Some(profile.into()), true).unwrap();
            let existing = session
                .fetch(EntryKind::Item, "mix", &name, false)
                .await
                .unwrap();
            let op = match (rand(3), existing.is_some()) {
                (0, true) => EntryOperation::Remove,
                (_, true) => EntryOperation::Replace,
                (_, false) => EntryOperation::Insert,
            };
            let (value, tags) = if op == EntryOperation::Remove {
                (None, None)
            } else {
                (Some(value.as_bytes()), Some(&tags[..]))
            };
            session
                .update(EntryKind::Item, op, "mix", &name, value, tags, expiry)
                .await
                .unwrap();
            session.close(true).await.unwrap();
        }

        let restored = restore(&store, &base, 7).await;
        let source = store.export().await.unwrap();
        assert_exports_equal(&source, &restored, 10_000);
        store
    });
}

#[test]
fn an_export_taken_during_writes_is_consistent() {
    with_store("concurrent", |store, _| async move {
        store.enable_journal().await.unwrap();
        for i in 0..200 {
            put(&store, DEFAULT, "pre", &format!("p{i}"), b"v").await;
        }
        // The export starts once the writer is halfway, while it is still writing.
        let written = std::sync::atomic::AtomicUsize::new(0);
        let writer = async {
            for i in 0..200 {
                put(&store, DEFAULT, "during", &format!("d{i}"), b"v").await;
                written.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        };
        let exporter = async {
            while written.load(std::sync::atomic::Ordering::SeqCst) < 100 {
                futures_lite::future::yield_now().await;
            }
            store.export().await
        };
        let (_, base) = futures_lite::future::zip(writer, exporter).await;
        let base = base.unwrap();
        // Every write here is one insert journaled from the start, so a consistent export
        // holds exactly as many entries as its head counts.
        let held = base.profiles.iter().map(|p| p.entries.len()).sum::<usize>() as u64;
        assert_eq!(held, base.head.unwrap().seq);
        let restored = restore(&store, &base, 50).await;
        let source = store.export().await.unwrap();
        assert_exports_equal(&source, &restored, 0);
        store
    });
}

#[test]
fn prune_keeps_later_rows_and_gaps_ask_for_a_rebase() {
    with_store("prune", |store, _| async move {
        store.enable_journal().await.unwrap();
        for i in 0..5 {
            put(&store, DEFAULT, "c", &format!("n{i}"), b"v").await;
        }
        assert_eq!(store.journal_prune(3).await.unwrap(), 3);
        let after_three = store.journal_changes(3, 100).await.unwrap();
        assert!(!after_three.rebase_needed);
        assert_eq!(after_three.changes.len(), 2);

        let behind = store.journal_changes(1, 100).await.unwrap();
        assert!(behind.rebase_needed && behind.changes.is_empty());
        let ahead = store.journal_changes(99, 100).await.unwrap();
        assert!(ahead.rebase_needed);
        assert!(journal::apply_changes(&store, &behind).await.is_err());

        assert_eq!(store.journal_prune(5).await.unwrap(), 2);
        let caught_up = store.journal_changes(5, 100).await.unwrap();
        assert!(!caught_up.rebase_needed && caught_up.changes.is_empty());
        store
    });
}

#[test]
fn the_journal_id_names_one_store() {
    let path = path("identity");
    block_on(async {
        let store = provision(&path, false).await;
        let first = store.enable_journal().await.unwrap().journal_id;
        assert_eq!(
            store.enable_journal().await.unwrap().journal_id,
            first,
            "enabling twice keeps the journal"
        );
        store.close().await.unwrap();

        let recreated = provision(&path, true).await;
        assert!(recreated.journal_head().await.unwrap().is_none());
        let second = recreated.enable_journal().await.unwrap().journal_id;
        assert_ne!(second, first);
        recreated.close().await.unwrap();
        SqliteStoreOptions::new(path.as_str())
            .unwrap()
            .remove_backend()
            .await
            .unwrap();
    });
}

#[test]
fn expiry_survives_and_expired_entries_stay_out() {
    with_store("expiry", |store, _| async move {
        store.enable_journal().await.unwrap();
        write(
            &store,
            DEFAULT,
            EntryKind::Item,
            EntryOperation::Insert,
            "c",
            "long",
            b"v",
            &[],
            Some(3_600_000),
        )
        .await;
        write(
            &store,
            DEFAULT,
            EntryKind::Item,
            EntryOperation::Insert,
            "c",
            "short",
            b"v",
            &[],
            Some(1),
        )
        .await;
        std::thread::sleep(Duration::from_millis(1100));

        let export = store.export().await.unwrap();
        let names: Vec<_> = export.profiles[0]
            .entries
            .iter()
            .map(|e| e.entry.name.as_str())
            .collect();
        assert_eq!(names, vec!["long"]);
        let left = export.profiles[0].entries[0].expires_at_ms.unwrap()
            - std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;
        assert!(left > 3_500_000 && left <= 3_600_000, "{left}");

        let restored = restore(&store, &export, 10).await;
        assert_exports_equal(&export, &restored, 10_000);
        store
    });
}

#[test]
fn a_store_without_the_journal_says_so() {
    with_store("off", |store, _| async move {
        assert!(store.journal_head().await.unwrap().is_none());
        assert!(store.journal_changes(0, 10).await.is_err());
        assert!(store.journal_prune(1).await.is_err());
        let export = store.export().await.unwrap();
        assert!(export.head.is_none());
        assert_eq!(export.default_profile, DEFAULT);
        store
    });
}
