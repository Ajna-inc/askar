//! Commits that wait at the same time share one witness advance.
//!
//! This binary holds one test: it installs a trigger on its witness table, and that DDL must
//! not queue behind (or in front of) another test's statements on the same table.
//!
//! Run with `AJNA_FRESHNESS_TEST_PG_URL` (see `freshness_support`); skipped otherwise.
#![cfg(feature = "postgres")]

mod freshness_support;

use askar_storage::{Backend, BackendSession};
use freshness_support::{base_url, bound_store, fetch, insert};
use std::time::{Duration, Instant};

/// RED before the fix. The witness is made slow (40 ms per
/// compare-and-advance, as a remote witness with a durable commit is); 16 tenants commit at
/// once. One advance per commit, one at a time, needs 16 × 40 ms.
#[test]
fn concurrent_committers_share_one_witness_advance() {
    freshness_support::run(concurrent_committers_share_one_witness_advance_on_runtime())
}
async fn concurrent_committers_share_one_witness_advance_on_runtime() {
    let Some(base) = base_url() else { return };
    const TENANTS: usize = 16;
    const ADVANCE: Duration = Duration::from_millis(40);
    let store = bound_store(&base, "").await;
    let tenants = store.profiles(TENANTS).await;
    let before = store.assert_agreement().await;
    let witness = freshness_support::admin(&store.witness_url).await;
    let function = format!("slow_{}", store.lineage.simple());
    sqlx::query(&format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN PERFORM pg_sleep({}); RETURN NEW; END $$",
        ADVANCE.as_secs_f64()
    ))
    .execute(&witness)
    .await
    .unwrap();
    sqlx::query(&format!(
        "CREATE TRIGGER {function} BEFORE UPDATE ON askar_freshness_witness_v1 FOR EACH ROW \
         WHEN (OLD.lineage = '{}') EXECUTE FUNCTION {function}()",
        store.lineage
    ))
    .execute(&witness)
    .await
    .unwrap();

    // Every transaction is open and has written before the first one commits.
    let opened = tokio::time::timeout(Duration::from_secs(10), async {
        let mut sessions = Vec::new();
        for tenant in &tenants {
            let mut session = store.backend.session(Some(tenant.clone()), true).unwrap();
            insert(&mut session, "row").await.unwrap();
            sessions.push(session);
        }
        sessions
    })
    .await;
    let Ok(sessions) = opened else {
        panic!("{TENANTS} tenants could not hold open writing transactions at the same time");
    };
    let started = Instant::now();
    let mut tasks = Vec::new();
    for mut session in sessions {
        tasks.push(tokio::spawn(async move { session.close(true).await }));
    }
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    let elapsed = started.elapsed();
    sqlx::query(&format!(
        "DROP TRIGGER {function} ON askar_freshness_witness_v1"
    ))
    .execute(&witness)
    .await
    .unwrap();
    witness.close().await;
    let advances = store.assert_agreement().await - before;
    eprintln!("{TENANTS} concurrent commits: {elapsed:?}, {advances} witness advances");
    assert!(
        elapsed < ADVANCE * (TENANTS as u32) / 2,
        "{TENANTS} concurrent commits took {elapsed:?} against a {ADVANCE:?} witness: \
         one advance per commit"
    );
    assert!(
        advances < TENANTS as u64,
        "{advances} witness advances for {TENANTS} concurrent commits"
    );
    for tenant in &tenants {
        let mut session = store.backend.session(Some(tenant.clone()), false).unwrap();
        assert!(fetch(&mut session, "row").await.unwrap());
        session.close(false).await.unwrap();
    }
}
