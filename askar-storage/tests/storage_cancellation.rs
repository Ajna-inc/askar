//! A cancelled or dropped Askar session must never hand the next user of its
//! pooled connection a transaction state that differs from the database's.
//!
//! Every test uses a pool of exactly one connection, so the session opened
//! after the cancellation necessarily uses the connection the cancelled
//! session held (or its replacement, which the PostgreSQL tests count).
mod cancel_support;

use askar_storage::{
    any::{into_any_backend, AnyBackend},
    backend::{recovery_stats, RecoveryStats},
    entry::{EntryKind, EntryOperation},
    generate_raw_store_key, Backend, BackendSession, StoreKeyMethod,
};
use cancel_support::*;
use std::future::Future;
use std::time::Duration;

const CATEGORY: &str = "cancel";

async fn insert(db: &AnyBackend, txn: bool, name: &str) -> askar_storage::Error {
    let mut session = db.session(None, txn).unwrap();
    session
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            CATEGORY,
            name,
            Some(b"value"),
            None,
            None,
        )
        .await
        .expect_err("helper only used for failures")
}

async fn write(session: &mut askar_storage::any::AnyBackendSession, name: &str) {
    session
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            CATEGORY,
            name,
            Some(b"value"),
            None,
            None,
        )
        .await
        .expect("write");
}

async fn exists(db: &AnyBackend, name: &str) -> bool {
    let mut session = db.session(None, false).unwrap();
    let found = session
        .fetch(EntryKind::Item, CATEGORY, name, false)
        .await
        .expect("a plain read after the cancellation")
        .is_some();
    session.close(false).await.unwrap();
    found
}

/// The pool's next user can open a transaction, write, and commit.
async fn next_transaction_commits(db: &AnyBackend, name: &str) {
    let mut session = db.session(None, true).unwrap();
    session
        .fetch(EntryKind::Item, CATEGORY, name, true)
        .await
        .unwrap_or_else(|e| panic!("BEGIN on the reused connection failed: {e:?}"));
    write(&mut session, name).await;
    session.close(true).await.expect("commit");
    assert!(exists(db, name).await, "the next transaction was committed");
}

/// The pool's next user can write outside an explicit transaction.
async fn next_single_write_commits(db: &AnyBackend, name: &str) {
    let mut session = db.session(None, false).unwrap();
    session
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            CATEGORY,
            name,
            Some(b"value"),
            None,
            None,
        )
        .await
        .unwrap_or_else(|e| panic!("single write on the reused connection failed: {e:?}"));
    session.close(false).await.unwrap();
    assert!(exists(db, name).await);
}

// ---------------------------------------------------------------- PostgreSQL

struct Pg {
    db: AnyBackend,
    proxy: HoldProxy,
    direct: String,
}

async fn pg(schema: &str) -> Pg {
    let (_, _, upstream) = postgres_uris(None, schema);
    let proxy = HoldProxy::start(upstream).await;
    let (uri, direct, _) = postgres_uris(Some(proxy.addr()), schema);
    let key = generate_raw_store_key(None).unwrap();
    let db = askar_storage::backend::postgres::PostgresStoreOptions::new(uri.as_str())
        .unwrap()
        .provision(StoreKeyMethod::RawKey, key, None, true)
        .await
        .expect("provision PostgreSQL store");
    Pg {
        db: into_any_backend(db),
        proxy,
        direct,
    }
}

/// Drop `operation` while the server has received the statement containing
/// `marker` and its reply is held back.
async fn cancel_after_sent<F: Future>(proxy: &HoldProxy, marker: &str, operation: F) {
    proxy.arm(marker);
    tokio::pin!(operation);
    tokio::select! {
        biased;
        _ = proxy.held() => {}
        _ = &mut operation => panic!("{marker}: completed although its reply was held"),
    }
}

/// The interrupted connection was repaired (not closed), if one was expected.
async fn assert_recovered(before: RecoveryStats, expect_repair: bool) {
    // Recovery runs in the background; the pool hands the connection out only
    // after it, so by the time a later session has used it the count is final.
    let after = recovery_stats();
    assert_eq!(after.discarded, before.discarded, "no connection discarded");
    if expect_repair {
        assert!(
            after.repaired > before.repaired,
            "the connection was repaired"
        );
    }
}

async fn pg_assert_clean(pg: &Pg, connections_before: usize, next: &str) {
    // A plain read waits for the one pooled connection and leaves any
    // transaction the server still holds on it untouched.
    assert!(!exists(&pg.db, "probe").await);
    assert_eq!(
        idle_in_transaction(&pg.direct).await,
        0,
        "the returned connection must not still be inside a server transaction"
    );
    next_transaction_commits(&pg.db, next).await;
    next_single_write_commits(&pg.db, &format!("{next}-single")).await;
    assert_eq!(
        idle_in_transaction(&pg.direct).await,
        0,
        "no pooled server session may be left inside a transaction"
    );
    assert_eq!(
        pg.proxy.connections(),
        connections_before,
        "the cancelled session's connection was repaired and reused, not replaced"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable PostgreSQL in TENANT_FENCE_TEST_POSTGRES"]
async fn pg_cancelled_commit_leaves_a_reusable_connection() {
    let _serial = serial().await;
    let pg = pg("st_commit").await;
    let mut session = pg.db.session(None, true).unwrap();
    write(&mut session, "a").await;
    let before = pg.proxy.connections();
    let stats = recovery_stats();
    cancel_after_sent(&pg.proxy, "COMMIT", session.close(true)).await;
    drop(session);
    pg.proxy.release();
    // The server received COMMIT before the cancellation.
    assert!(exists(&pg.db, "a").await);
    pg_assert_clean(&pg, before, "b").await;
    assert_recovered(stats, true).await;
}

/// AUD-A F11 (A-6): repairing an interrupted connection is bounded. A peer
/// that never answers (a silently dead socket) must not keep the connection
/// checked out until TCP gives up: it is discarded and the pool replaces it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable PostgreSQL in TENANT_FENCE_TEST_POSTGRES"]
async fn pg_a_repair_that_gets_no_answer_is_abandoned_and_the_connection_replaced() {
    let _serial = serial().await;
    let pg = pg("rt_repair_bound").await;
    let mut session = pg.db.session(None, true).unwrap();
    write(&mut session, "a").await;
    let before = pg.proxy.connections();
    let stats = recovery_stats();
    cancel_after_sent(&pg.proxy, "COMMIT", session.close(true)).await;
    drop(session);
    // Replies stay held: the repair's own round trip is never answered.
    let discarded = tokio::time::timeout(Duration::from_secs(120), async {
        while recovery_stats().discarded == stats.discarded {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        discarded.is_ok(),
        "a repair that never gets an answer kept the connection checked out"
    );
    assert_eq!(recovery_stats().repaired, stats.repaired);
    pg.proxy.release();
    // The pool opens a replacement and serves transactions again.
    next_transaction_commits(&pg.db, "b").await;
    assert!(
        pg.proxy.connections() > before,
        "the unanswered connection was replaced"
    );
    assert_eq!(idle_in_transaction(&pg.direct).await, 0);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable PostgreSQL in TENANT_FENCE_TEST_POSTGRES"]
async fn pg_cancelled_rollback_leaves_a_reusable_connection() {
    let _serial = serial().await;
    let pg = pg("st_rollback").await;
    let mut session = pg.db.session(None, true).unwrap();
    write(&mut session, "a").await;
    let before = pg.proxy.connections();
    let stats = recovery_stats();
    cancel_after_sent(&pg.proxy, "ROLLBACK", session.close(false)).await;
    drop(session);
    pg.proxy.release();
    assert!(!exists(&pg.db, "a").await);
    pg_assert_clean(&pg, before, "b").await;
    assert_recovered(stats, true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable PostgreSQL in TENANT_FENCE_TEST_POSTGRES"]
async fn pg_cancelled_begin_leaves_a_reusable_connection() {
    let _serial = serial().await;
    let pg = pg("st_begin").await;
    // Open the pool's connection first so the count below is meaningful.
    assert!(!exists(&pg.db, "warm").await);
    let before = pg.proxy.connections();
    let stats = recovery_stats();
    let mut session = pg.db.session(None, true).unwrap();
    cancel_after_sent(
        &pg.proxy,
        "BEGIN",
        session.fetch(EntryKind::Item, CATEGORY, "a", true),
    )
    .await;
    drop(session);
    pg.proxy.release();
    pg_assert_clean(&pg, before, "b").await;
    assert_recovered(stats, true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable PostgreSQL in TENANT_FENCE_TEST_POSTGRES"]
async fn pg_cancelled_statement_inside_transaction_rolls_back() {
    let _serial = serial().await;
    let pg = pg("st_statement").await;
    let mut session = pg.db.session(None, true).unwrap();
    // BEGIN plus a locking read, without preparing the INSERT: its text must
    // still be sent so the proxy can recognise it.
    assert!(session
        .fetch(EntryKind::Item, CATEGORY, "second", true)
        .await
        .unwrap()
        .is_none());
    let before = pg.proxy.connections();
    let stats = recovery_stats();
    cancel_after_sent(
        &pg.proxy,
        "INSERT INTO items",
        session.update(
            EntryKind::Item,
            EntryOperation::Insert,
            CATEGORY,
            "second",
            Some(b"value"),
            None,
            None,
        ),
    )
    .await;
    drop(session);
    pg.proxy.release();
    assert!(
        !exists(&pg.db, "second").await,
        "the executed but uncommitted INSERT was rolled back"
    );
    pg_assert_clean(&pg, before, "b").await;
    assert_recovered(stats, false).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable PostgreSQL in TENANT_FENCE_TEST_POSTGRES"]
async fn pg_cancelled_single_write_commit_leaves_a_reusable_connection() {
    let _serial = serial().await;
    let pg = pg("st_single_commit").await;
    assert!(!exists(&pg.db, "warm").await);
    let before = pg.proxy.connections();
    let stats = recovery_stats();
    let mut session = pg.db.session(None, false).unwrap();
    cancel_after_sent(
        &pg.proxy,
        "COMMIT",
        session.update(
            EntryKind::Item,
            EntryOperation::Insert,
            CATEGORY,
            "a",
            Some(b"value"),
            None,
            None,
        ),
    )
    .await;
    drop(session);
    pg.proxy.release();
    assert!(exists(&pg.db, "a").await);
    pg_assert_clean(&pg, before, "b").await;
    assert_recovered(stats, true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable PostgreSQL in TENANT_FENCE_TEST_POSTGRES"]
async fn pg_cancelled_single_write_begin_leaves_a_reusable_connection() {
    let _serial = serial().await;
    let pg = pg("st_single_begin").await;
    assert!(!exists(&pg.db, "warm").await);
    let before = pg.proxy.connections();
    let stats = recovery_stats();
    let mut session = pg.db.session(None, false).unwrap();
    cancel_after_sent(
        &pg.proxy,
        "BEGIN",
        session.update(
            EntryKind::Item,
            EntryOperation::Insert,
            CATEGORY,
            "a",
            Some(b"value"),
            None,
            None,
        ),
    )
    .await;
    drop(session);
    pg.proxy.release();
    assert!(!exists(&pg.db, "a").await);
    pg_assert_clean(&pg, before, "b").await;
    assert_recovered(stats, true).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a disposable PostgreSQL in TENANT_FENCE_TEST_POSTGRES"]
async fn pg_dropped_transaction_rolls_back_and_connection_is_reused() {
    let _serial = serial().await;
    let pg = pg("st_dropped").await;
    let mut session = pg.db.session(None, true).unwrap();
    write(&mut session, "a").await;
    let before = pg.proxy.connections();
    let stats = recovery_stats();
    drop(session);
    assert!(!exists(&pg.db, "a").await);
    pg_assert_clean(&pg, before, "b").await;
    assert_recovered(stats, false).await;
}

// -------------------------------------------------------------------- SQLite

struct Lite {
    db: AnyBackend,
    path: std::path::PathBuf,
    _dir: tempfile::TempDir,
}

async fn sqlite() -> Lite {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cancel.db");
    let uri = format!(
        "sqlite://{}?journal_mode=delete&max_connections=1&min_connections=1&busy_timeout=20000",
        path.display()
    );
    let key = generate_raw_store_key(None).unwrap();
    let db = askar_storage::backend::sqlite::SqliteStoreOptions::new(uri.as_str())
        .unwrap()
        .provision(StoreKeyMethod::RawKey, key, None, true)
        .await
        .expect("provision SQLite store");
    Lite {
        db: into_any_backend(db),
        path,
        _dir: dir,
    }
}

/// Drop `operation` while SQLite is executing its COMMIT, blocked by `reader`.
async fn cancel_blocked_commit<F: Future>(reader: SqliteReader, operation: F) {
    // The COMMIT cannot finish while the reader holds its lock, so this bound
    // never decides the outcome; it only gives the future time to issue it.
    let outcome = tokio::time::timeout(Duration::from_millis(300), operation).await;
    assert!(
        outcome.is_err(),
        "COMMIT finished while a reader held SHARED"
    );
    reader.release().await;
}

/// A later transaction that is abandoned must still roll back, and the pool's
/// next user must be able to BEGIN.
async fn sqlite_assert_clean(lite: &Lite) {
    let mut abandoned = lite.db.session(None, true).unwrap();
    write(&mut abandoned, "abandoned").await;
    drop(abandoned);
    assert!(
        !exists(&lite.db, "abandoned").await,
        "an abandoned transaction's write must not be visible"
    );
    next_transaction_commits(&lite.db, "b").await;
    next_single_write_commits(&lite.db, "c").await;
    let err = insert(&lite.db, false, "c").await;
    assert_eq!(err.kind(), askar_storage::ErrorKind::Duplicate);
    next_transaction_commits(&lite.db, "d").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_cancelled_commit_leaves_a_reusable_connection() {
    let _serial = serial().await;
    let lite = sqlite().await;
    let mut session = lite.db.session(None, true).unwrap();
    write(&mut session, "a").await;
    let reader = SqliteReader::hold(&lite.path).await;
    let stats = recovery_stats();
    cancel_blocked_commit(reader, session.close(true)).await;
    drop(session);
    assert!(exists(&lite.db, "a").await, "SQLite finished the COMMIT");
    assert_recovered(stats, true).await;
    sqlite_assert_clean(&lite).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_cancelled_single_write_commit_leaves_a_reusable_connection() {
    let _serial = serial().await;
    let lite = sqlite().await;
    assert!(!exists(&lite.db, "warm").await);
    let reader = SqliteReader::hold(&lite.path).await;
    let stats = recovery_stats();
    let mut session = lite.db.session(None, false).unwrap();
    cancel_blocked_commit(
        reader,
        session.update(
            EntryKind::Item,
            EntryOperation::Insert,
            CATEGORY,
            "a",
            Some(b"value"),
            None,
            None,
        ),
    )
    .await;
    drop(session);
    assert!(exists(&lite.db, "a").await);
    assert_recovered(stats, true).await;
    sqlite_assert_clean(&lite).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_dropped_transaction_rolls_back_and_connection_is_reused() {
    let _serial = serial().await;
    let lite = sqlite().await;
    let mut session = lite.db.session(None, true).unwrap();
    write(&mut session, "a").await;
    drop(session);
    assert!(!exists(&lite.db, "a").await);
    sqlite_assert_clean(&lite).await;
}
