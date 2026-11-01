//! A witness-bound PostgreSQL store must not make tenants wait for each other.
//!
//! Before the fix every transactional session took `SELECT … FOR UPDATE` on the single
//! store-wide freshness head at admission and held it to COMMIT, read-only transactions
//! included: the whole store ran one transaction at a time, and a transaction that waited on
//! the network stopped every other tenant. These tests hold that open and assert the bounds
//! the old protocol cannot meet, and that the anti-rollback property is still enforced.
//!
//! Run with `AJNA_FRESHNESS_TEST_PG_URL` (see `freshness_support`); skipped otherwise.
#![cfg(feature = "postgres")]

mod freshness_support;

use askar_storage::{Backend, BackendSession};
use freshness_support::{base_url, bound_store, fetch, insert, open, seed};
use std::time::{Duration, Instant};

/// (a) RED before the fix: a read-only transaction and a plain read on tenant B finish while
/// tenant A's writing transaction is open and uncommitted, and a read-only transaction holds
/// no row lock on the head.
#[test]
fn read_only_work_takes_no_head_lock() {
    freshness_support::run(read_only_work_takes_no_head_lock_on_runtime())
}
async fn read_only_work_takes_no_head_lock_on_runtime() {
    let Some(base) = base_url() else { return };
    let store = bound_store(&base, "").await;
    let tenants = store.profiles(2).await;
    seed(&store.backend, &tenants[1], "row").await;

    let mut writer = store.backend.session(Some(tenants[0].clone()), true).unwrap();
    insert(&mut writer, "uncommitted").await.unwrap();

    let started = Instant::now();
    let read_only = tokio::time::timeout(Duration::from_millis(1500), async {
        let mut session = store.backend.session(Some(tenants[1].clone()), true).unwrap();
        assert!(fetch(&mut session, "row").await.unwrap());
        assert!(!fetch(&mut session, "absent").await.unwrap());
        session.close(false).await.unwrap();
        let mut session = store.backend.session(Some(tenants[1].clone()), true).unwrap();
        assert!(fetch(&mut session, "row").await.unwrap());
        session.close(true).await.unwrap();
    })
    .await;
    assert!(
        read_only.is_ok(),
        "tenant B's read-only transactions waited more than {:?} behind tenant A's open \
         writing transaction",
        started.elapsed()
    );
    let started = Instant::now();
    let plain = tokio::time::timeout(Duration::from_millis(1500), async {
        let mut session = store.backend.session(Some(tenants[1].clone()), false).unwrap();
        assert!(fetch(&mut session, "row").await.unwrap());
        session.close(false).await.unwrap();
    })
    .await;
    assert!(
        plain.is_ok(),
        "tenant B's plain read waited more than {:?}",
        started.elapsed()
    );

    // An open read-only transaction holds no lock on the head row: another connection takes
    // it without waiting.
    writer.close(true).await.unwrap();
    let mut reader = store.backend.session(Some(tenants[1].clone()), true).unwrap();
    assert!(fetch(&mut reader, "row").await.unwrap());
    let side = freshness_support::admin(&store.store_url).await;
    let mut tx = side.begin().await.unwrap();
    let locked = sqlx::query(
        "SELECT value FROM config WHERE name = 'askar_freshness_head_v1' FOR UPDATE NOWAIT",
    )
    .fetch_one(&mut *tx)
    .await;
    assert!(
        locked.is_ok(),
        "an open read-only transaction holds the store-wide head row: {:?}",
        locked.err()
    );
    tx.rollback().await.unwrap();
    side.close().await;
    reader.close(false).await.unwrap();
    store.assert_agreement().await;
}

/// (c) RED before the fix: a transaction that waits (network I/O) between its writes and its
/// commit does not delay another tenant's writing transaction.
#[test]
fn a_transaction_waiting_on_io_does_not_block_another_tenant() {
    freshness_support::run(a_transaction_waiting_on_io_does_not_block_another_tenant_on_runtime())
}
async fn a_transaction_waiting_on_io_does_not_block_another_tenant_on_runtime() {
    let Some(base) = base_url() else { return };
    let store = bound_store(&base, "").await;
    let tenants = store.profiles(2).await;
    let before = store.assert_agreement().await;

    let slow = tokio::spawn({
        let backend = store.backend.clone();
        let tenant = tenants[0].clone();
        async move {
            let mut session = backend.session(Some(tenant), true).unwrap();
            insert(&mut session, "before-io").await.unwrap();
            tokio::time::sleep(Duration::from_millis(1500)).await;
            insert(&mut session, "after-io").await.unwrap();
            session.close(true).await.unwrap();
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    let mut session = store.backend.session(Some(tenants[1].clone()), true).unwrap();
    insert(&mut session, "other-tenant").await.unwrap();
    session.close(true).await.unwrap();
    let waited = started.elapsed();
    assert!(
        waited < Duration::from_millis(500),
        "tenant B's writing transaction took {waited:?} while tenant A's transaction was \
         waiting on I/O"
    );
    slow.await.unwrap();
    assert_eq!(store.assert_agreement().await, before + 2);
}

/// (b) RED before the fix: 8 tenants × 4 concurrent writing transactions, each doing 5 reads,
/// 50 ms of application work and 1 write. Serialized store-wide that is at least 32 × 50 ms;
/// with only same-tenant transactions serialized it is about 4 × 50 ms.
#[test]
fn tenants_times_writers_finish_within_a_parallel_bound() {
    freshness_support::run(tenants_times_writers_finish_within_a_parallel_bound_on_runtime())
}
async fn tenants_times_writers_finish_within_a_parallel_bound_on_runtime() {
    let Some(base) = base_url() else { return };
    const TENANTS: usize = 8;
    const WRITERS: usize = 4;
    const WORK: Duration = Duration::from_millis(50);
    let store = bound_store(&base, "").await;
    let tenants = store.profiles(TENANTS).await;
    for tenant in &tenants {
        seed(&store.backend, tenant, "row").await;
    }
    let before = store.assert_agreement().await;

    let started = Instant::now();
    let mut tasks = Vec::new();
    for tenant in &tenants {
        for writer in 0..WRITERS {
            let backend = store.backend.clone();
            let tenant = tenant.clone();
            tasks.push(tokio::spawn(async move {
                let mut session = backend.session(Some(tenant), true).unwrap();
                for _ in 0..5 {
                    assert!(fetch(&mut session, "row").await.unwrap());
                }
                tokio::time::sleep(WORK).await;
                insert(&mut session, &format!("written-{writer}")).await.unwrap();
                session.close(true).await.unwrap();
            }));
        }
    }
    for task in tasks {
        task.await.unwrap();
    }
    let elapsed = started.elapsed();
    let serial = WORK * (TENANTS * WRITERS) as u32;
    eprintln!(
        "{TENANTS} tenants x {WRITERS} writing transactions: {elapsed:?} (store-wide serial \
         floor {serial:?})"
    );
    assert!(
        elapsed < serial / 2,
        "{TENANTS} tenants x {WRITERS} writers took {elapsed:?}; a store that serializes \
         every transaction needs at least {serial:?}"
    );
    // Commits that waited together share an advance; none commits without one.
    let advances = store.assert_agreement().await - before;
    assert!(
        (1..=(TENANTS * WRITERS) as u64).contains(&advances),
        "{advances} head advances for {} commits",
        TENANTS * WRITERS
    );
    for tenant in &tenants {
        let mut session = store.backend.session(Some(tenant.clone()), false).unwrap();
        for writer in 0..WRITERS {
            assert!(fetch(&mut session, &format!("written-{writer}")).await.unwrap());
        }
        session.close(false).await.unwrap();
    }
}

/// (f) RED before the fix: the witness answers late (its row is locked past the client's
/// 5 s deadline), so the compare-and-advance's outcome is unknown when the deadline fires.
/// The commit must learn the outcome and finish, never roll back beside an advanced witness.
#[test]
fn an_ambiguous_witness_outcome_is_resolved_not_assumed_failed() {
    freshness_support::run(an_ambiguous_witness_outcome_is_resolved_not_assumed_failed_on_runtime())
}
async fn an_ambiguous_witness_outcome_is_resolved_not_assumed_failed_on_runtime() {
    let Some(base) = base_url() else { return };
    let store = bound_store(&base, "").await;
    let before = store.assert_agreement().await;
    let witness = freshness_support::admin(&store.witness_url).await;
    let mut hold = witness.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM askar_freshness_witness_v1 WHERE lineage = $1 FOR UPDATE")
        .bind(store.lineage.to_string())
        .fetch_one(&mut *hold)
        .await
        .unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5600)).await;
        hold.rollback().await.unwrap();
    });
    let mut session = store.backend.session(None, true).unwrap();
    insert(&mut session, "ambiguous").await.unwrap();
    let committed = session.close(true).await;
    release.await.unwrap();
    witness.close().await;
    assert!(
        committed.is_ok(),
        "a late witness answer failed the commit instead of being resolved: {:?}",
        committed.err().map(|e| e.to_string())
    );
    assert_eq!(store.assert_agreement().await, before + 1);
    let mut session = store.backend.session(None, false).unwrap();
    assert!(fetch(&mut session, "ambiguous").await.unwrap());
    session.close(false).await.unwrap();
}

/// (e) Guard, green before and after: a restored older copy refuses at open; an already-open
/// store whose witness has moved on refuses writes at once and reads once its lease is over.
#[test]
fn a_store_behind_its_witness_is_refused() {
    freshness_support::run(a_store_behind_its_witness_is_refused_on_runtime())
}
async fn a_store_behind_its_witness_is_refused_on_runtime() {
    let Some(base) = base_url() else { return };
    const LEASE: Duration = Duration::from_millis(300);
    let store = bound_store(&base, "&freshness_read_lease_ms=300").await;
    let profile = store.backend.get_active_profile();
    seed(&store.backend, &profile, "row").await;

    // An older copy: the database as it is now, then the live store moves on.
    store.backend.close().await.unwrap();
    let clone = format!("clone_{}", uuid::Uuid::new_v4().simple());
    let pool = freshness_support::admin(&base).await;
    sqlx::query(&format!(
        "CREATE DATABASE {clone} TEMPLATE {}",
        store.name
    ))
    .execute(&pool)
    .await
    .expect("copy the store");
    pool.close().await;
    let live = open(&store.pinned, &store.key).await.unwrap();
    seed(&live, &profile, "after-the-copy").await;
    let stale_url = store.pinned.replace(&store.name, &clone);
    let started = Instant::now();
    let refused = open(&stale_url, &store.key).await;
    let message = refused.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        message.contains("Store freshness refused"),
        "a restored older copy opened: {message:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));

    // The live store with a warm lease, then the witness advances without it (the real store
    // moved on elsewhere; this process is attached to a copy at the verified head).
    let mut reader = live.session(Some(profile.clone()), false).unwrap();
    assert!(fetch(&mut reader, "row").await.unwrap());
    let mut pending = live.session(Some(profile.clone()), true).unwrap();
    insert(&mut pending, "stale-writer").await.unwrap();
    let head = store.local_head().await;
    store
        .witness
        .advance(&head, &head.next().unwrap())
        .await
        .unwrap();
    // A writer admitted on the stale head cannot commit, at once.
    let started = Instant::now();
    let commit = pending.close(true).await;
    let message = commit.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        message.contains("reshness"),
        "a writer on a stale head committed: {message:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(store.local_head().await, head, "the stale commit left the local head alone");
    // A read is refused no later than the lease plus the forward-race budget.
    tokio::time::sleep(LEASE + Duration::from_millis(50)).await;
    let started = Instant::now();
    let read = fetch(&mut reader, "row").await;
    let message = read.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        message.contains("Store freshness refused"),
        "a store behind its witness served a read after its lease: {message:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    let mut fresh = live.session(Some(profile.clone()), false).unwrap();
    assert!(fetch(&mut fresh, "row").await.is_err());
    let mut absent = live.session(Some(profile), false).unwrap();
    assert!(
        !matches!(fetch(&mut absent, "stale-writer").await, Ok(true)),
        "the refused commit's row is visible"
    );
    assert!(open(&store.pinned, &store.key).await.is_err());
}

async fn set_local_head(store: &freshness_support::Bound, head: &askar_storage::backend::freshness::Head) {
    let pool = freshness_support::admin(&store.store_url).await;
    sqlx::query("UPDATE config SET value = $1 WHERE name = 'askar_freshness_head_v1'")
        .bind(serde_json::to_string(head).unwrap())
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

/// Guard for the read lease: an older head under a running process with a warm lease is not
/// the confirmed head, so the witness is asked and the store is refused: on a new session,
/// on a session that was already reading, and at a writer's commit.
#[test]
fn a_restored_older_head_is_refused_despite_a_warm_lease() {
    freshness_support::run(a_restored_older_head_is_refused_despite_a_warm_lease_on_runtime())
}
async fn a_restored_older_head_is_refused_despite_a_warm_lease_on_runtime() {
    let Some(base) = base_url() else { return };
    let store = bound_store(&base, "&freshness_read_lease_ms=60000").await;
    let profile = store.backend.get_active_profile();
    let older = store.local_head().await;
    seed(&store.backend, &profile, "row").await;
    seed(&store.backend, &profile, "later").await;
    let current = store.local_head().await;
    let mut retained = store.backend.session(Some(profile.clone()), false).unwrap();
    assert!(fetch(&mut retained, "row").await.unwrap());

    set_local_head(&store, &older).await;
    let refused = |result: Result<bool, askar_storage::Error>| {
        let message = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(
            message.contains("Store freshness refused"),
            "an older head was served under a warm lease: {message:?}"
        );
    };
    refused(fetch(&mut retained, "row").await);
    let mut fresh = store.backend.session(Some(profile.clone()), false).unwrap();
    refused(fetch(&mut fresh, "row").await);
    let mut transaction = store.backend.session(Some(profile.clone()), true).unwrap();
    refused(fetch(&mut transaction, "row").await);
    drop(transaction);
    assert_eq!(store.witness_head().await, (current.sequence, current.token));

    // The same process serves again once the store is the current one.
    set_local_head(&store, &current).await;
    let mut session = store.backend.session(Some(profile.clone()), true).unwrap();
    assert!(fetch(&mut session, "later").await.unwrap());
    insert(&mut session, "after").await.unwrap();
    session.close(true).await.unwrap();
    assert_eq!(store.assert_agreement().await, current.sequence + 1);
}

/// Guard for the profile-key cache on a bound store: a profile removed and created again
/// under the same name never resolves to the key cached for the old one, and a session that
/// was using the old profile is refused.
#[test]
fn a_recreated_profile_never_resolves_to_a_cached_key() {
    freshness_support::run(a_recreated_profile_never_resolves_to_a_cached_key_on_runtime())
}
async fn a_recreated_profile_never_resolves_to_a_cached_key_on_runtime() {
    let Some(base) = base_url() else { return };
    let store = bound_store(&base, "").await;
    let observer = open(&store.pinned, &store.key).await.unwrap();
    let name = "recreated".to_string();
    store.backend.create_profile(Some(name.clone())).await.unwrap();
    // The observer's cache holds the first profile's key.
    let mut retained = observer.session(Some(name.clone()), false).unwrap();
    insert(&mut retained, "old").await.unwrap();
    assert!(fetch(&mut retained, "old").await.unwrap());
    let mut pending = observer.session(Some(name.clone()), false).unwrap();

    assert!(store.backend.remove_profile(name.clone()).await.unwrap());
    store.backend.create_profile(Some(name.clone())).await.unwrap();

    assert!(fetch(&mut retained, "old").await.is_err());
    assert!(insert(&mut retained, "pollution").await.is_err());
    // A session that had not touched the old profile works with the new one, under the new
    // key: the writer's handle, which never saw the old key, reads what it wrote.
    insert(&mut pending, "new").await.unwrap();
    assert!(fetch(&mut pending, "new").await.unwrap());
    assert!(!fetch(&mut pending, "old").await.unwrap());
    let mut writer = store.backend.session(Some(name.clone()), false).unwrap();
    assert!(fetch(&mut writer, "new").await.unwrap());
    let mut again = observer.session(Some(name), true).unwrap();
    assert!(fetch(&mut again, "new").await.unwrap());
    again.close(false).await.unwrap();
    store.assert_agreement().await;
}

/// Guard, unchanged behaviour: when the witness has advanced and the local COMMIT then fails,
/// nothing rewinds the witness and the store is refused at once, whatever the lease.
#[test]
fn a_failed_local_commit_after_the_advance_fails_closed() {
    freshness_support::run(a_failed_local_commit_after_the_advance_fails_closed_on_runtime())
}
async fn a_failed_local_commit_after_the_advance_fails_closed_on_runtime() {
    let Some(base) = base_url() else { return };
    let store = bound_store(&base, "&freshness_read_lease_ms=60000").await;
    let profile = store.backend.get_active_profile();
    seed(&store.backend, &profile, "row").await;
    let before = store.local_head().await;
    let pool = freshness_support::admin(&store.store_url).await;
    sqlx::query(
        "CREATE FUNCTION fail_head_commit() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'injected commit failure'; END $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE CONSTRAINT TRIGGER fail_head_commit AFTER UPDATE ON config \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW \
         WHEN (NEW.name = 'askar_freshness_head_v1') EXECUTE FUNCTION fail_head_commit()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let mut session = store.backend.session(Some(profile.clone()), true).unwrap();
    insert(&mut session, "lost").await.unwrap();
    assert!(session.close(true).await.is_err());
    sqlx::query("DROP TRIGGER fail_head_commit ON config")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    assert_eq!(store.local_head().await, before, "the failed COMMIT kept the old head");
    assert_eq!(store.witness_head().await.0, before.sequence + 1);
    let mut reader = store.backend.session(Some(profile.clone()), false).unwrap();
    let message = fetch(&mut reader, "row")
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        message.contains("Store freshness refused"),
        "a store behind its witness served a read: {message:?}"
    );
    let mut writer = store.backend.session(Some(profile), true).unwrap();
    assert!(
        !matches!(insert(&mut writer, "after").await, Ok(()))
            || writer.close(true).await.is_err(),
        "a store behind its witness committed"
    );
    assert!(open(&store.pinned, &store.key).await.is_err());
}

/// RED before the fix: a caller that stops waiting for its commit (a timeout around the
/// transaction) while the witness is slow must not leave the witness advanced beside a
/// rolled-back transaction. The commit finishes as one piece, or not at all.
#[test]
fn a_caller_that_stops_waiting_cannot_split_a_commit() {
    freshness_support::run(a_caller_that_stops_waiting_cannot_split_a_commit_on_runtime())
}
async fn a_caller_that_stops_waiting_cannot_split_a_commit_on_runtime() {
    let Some(base) = base_url() else { return };
    let store = bound_store(&base, "").await;
    let profile = store.backend.get_active_profile();
    let before = store.assert_agreement().await;
    let witness = freshness_support::admin(&store.witness_url).await;
    let mut hold = witness.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM askar_freshness_witness_v1 WHERE lineage = $1 FOR UPDATE")
        .bind(store.lineage.to_string())
        .fetch_one(&mut *hold)
        .await
        .unwrap();
    let mut session = store.backend.session(Some(profile.clone()), true).unwrap();
    insert(&mut session, "abandoned").await.unwrap();
    let abandoned =
        tokio::time::timeout(Duration::from_millis(200), session.close(true)).await;
    assert!(abandoned.is_err(), "the commit did not wait for the witness");
    drop(session);
    tokio::time::sleep(Duration::from_millis(800)).await;
    hold.rollback().await.unwrap();
    witness.close().await;
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let local = store.local_head().await;
    let external = store.witness_head().await;
    assert_eq!(
        (local.sequence, local.token),
        external,
        "the abandoned commit advanced the witness and rolled back locally"
    );
    assert_eq!(local.sequence, before + 1, "the abandoned commit completed");
    let mut reader = store.backend.session(Some(profile.clone()), false).unwrap();
    assert!(fetch(&mut reader, "abandoned").await.unwrap());
    seed(&store.backend, &profile, "afterwards").await;
    assert_eq!(store.assert_agreement().await, before + 2);
}
