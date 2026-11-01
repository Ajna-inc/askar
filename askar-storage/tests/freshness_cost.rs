//! What a witness-bound PostgreSQL store costs per operation, counted at the servers.
//!
//! Statements are counted with `pg_stat_statements` on the store database and on the witness
//! database (start the test PostgreSQL with
//! `-c shared_preload_libraries=pg_stat_statements`); without it the test is skipped. Only
//! top-level statements are counted: each is one round trip from the client. This
//! binary holds one test so that nothing else talks to its witness while it counts.
//!
//! Run with `AJNA_FRESHNESS_TEST_PG_URL` (see `freshness_support`); skipped otherwise.
#![cfg(feature = "postgres")]

mod freshness_support;

use askar_storage::{Backend, BackendSession};
use freshness_support::{admin, base_url, bound_store, fetch, insert, open, seed, Bound};
use std::time::{Duration, Instant};

struct Counter {
    pool: sqlx::PgPool,
    store: String,
    witness: String,
}
impl Counter {
    async fn calls(&self, database: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COALESCE(SUM(s.calls), 0)::bigint FROM pg_stat_statements s \
             JOIN pg_database d ON d.oid = s.dbid WHERE d.datname = $1 AND s.toplevel",
        )
        .bind(database)
        .fetch_one(&self.pool)
        .await
        .expect("read pg_stat_statements")
    }
    async fn now(&self) -> (i64, i64) {
        (self.calls(&self.store).await, self.calls(&self.witness).await)
    }
    /// Statements issued since `from`: (store, witness).
    async fn since(&self, from: (i64, i64)) -> (i64, i64) {
        let now = self.now().await;
        (now.0 - from.0, now.1 - from.1)
    }
}

async fn counter(base: &str, store: &Bound) -> Option<Counter> {
    let pool = admin(base).await;
    if sqlx::query("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
        .execute(&pool)
        .await
        .is_err()
        || sqlx::query("SELECT 1 FROM pg_stat_statements LIMIT 1")
            .execute(&pool)
            .await
            .is_err()
    {
        eprintln!("skipped: pg_stat_statements is not loaded on the test PostgreSQL");
        return None;
    }
    let witness = store
        .witness_url
        .rsplit_once('/')
        .unwrap()
        .1
        .split('?')
        .next()
        .unwrap()
        .to_owned();
    Some(Counter {
        pool,
        store: store.name.clone(),
        witness,
    })
}

/// (d) RED before the fix. Ceilings, for a store whose read lease is warm:
///
/// | operation | store statements | witness queries |
/// |---|---|---|
/// | plain fetch on a fresh session | 3 | 0 |
/// | further fetch on that session | 2 | 0 |
/// | read-only transaction with k reads | 3 + k | 0 |
/// | transaction with 1 read and 1 write | 7 | 1 |
///
/// then: 200 concurrent reads on a cold lease share the witness check, and a committer that
/// cannot take the head fails in bounded time before it touches the witness.
#[test]
fn statement_budgets() {
    freshness_support::run(statement_budgets_on_runtime())
}
async fn statement_budgets_on_runtime() {
    let Some(base) = base_url() else { return };
    const ROUNDS: i64 = 20;
    const READS: i64 = 5;
    std::env::set_var("ASKAR_FRESHNESS_COMMIT_LOCK_WAIT_MS", "500");
    let store = bound_store(&base, "&freshness_read_lease_ms=60000").await;
    let Some(counter) = counter(&base, &store).await else { return };
    let tenants = store.profiles(2).await;
    let tenant = tenants[0].clone();
    seed(&store.backend, &tenant, "row").await;
    // Warm every statement and the lease.
    for _ in 0..3 {
        let mut session = store.backend.session(Some(tenant.clone()), false).unwrap();
        assert!(fetch(&mut session, "row").await.unwrap());
        session.close(false).await.unwrap();
    }
    let mut failures = Vec::new();
    let mut check = |name: &str, measured: f64, ceiling: f64| {
        eprintln!("{name}: {measured:.2} (ceiling {ceiling})");
        if measured > ceiling {
            failures.push(format!("{name}: {measured:.2} > {ceiling}"));
        }
    };

    let from = counter.now().await;
    for _ in 0..ROUNDS {
        let mut session = store.backend.session(Some(tenant.clone()), false).unwrap();
        assert!(fetch(&mut session, "row").await.unwrap());
        session.close(false).await.unwrap();
    }
    let (s, w) = counter.since(from).await;
    check("plain fetch, store statements", s as f64 / ROUNDS as f64, 3.0);
    check("plain fetch, witness queries", w as f64 / ROUNDS as f64, 0.0);

    let from = counter.now().await;
    let mut session = store.backend.session(Some(tenant.clone()), false).unwrap();
    assert!(fetch(&mut session, "row").await.unwrap());
    let first = counter.since(from).await;
    let from = counter.now().await;
    for _ in 0..ROUNDS {
        assert!(fetch(&mut session, "row").await.unwrap());
    }
    session.close(false).await.unwrap();
    let (s, w) = counter.since(from).await;
    let _ = first;
    check("further fetch on an open session, store statements", s as f64 / ROUNDS as f64, 2.0);
    check("further fetch on an open session, witness queries", w as f64 / ROUNDS as f64, 0.0);

    let from = counter.now().await;
    for _ in 0..ROUNDS {
        let mut session = store.backend.session(Some(tenant.clone()), true).unwrap();
        for _ in 0..READS {
            assert!(fetch(&mut session, "row").await.unwrap());
        }
        session.close(true).await.unwrap();
    }
    let (s, w) = counter.since(from).await;
    check(
        "read-only transaction with 5 reads, store statements",
        s as f64 / ROUNDS as f64,
        (3 + READS) as f64,
    );
    check(
        "read-only transaction with 5 reads, witness queries",
        w as f64 / ROUNDS as f64,
        0.0,
    );

    let from = counter.now().await;
    let started = Instant::now();
    for round in 0..ROUNDS {
        let mut session = store.backend.session(Some(tenant.clone()), true).unwrap();
        assert!(fetch(&mut session, "row").await.unwrap());
        insert(&mut session, &format!("written-{round}")).await.unwrap();
        session.close(true).await.unwrap();
    }
    let per_commit = started.elapsed() / ROUNDS as u32;
    let (s, w) = counter.since(from).await;
    check(
        "transaction with 1 read and 1 write, store statements",
        s as f64 / ROUNDS as f64,
        7.0,
    );
    check(
        "transaction with 1 read and 1 write, witness queries",
        w as f64 / ROUNDS as f64,
        1.0,
    );
    eprintln!("sequential writing transaction: {per_commit:?} each");

    // Throughput, reported: 16 tenants each committing 25 transactions, all at once.
    let mut writers = Vec::new();
    for i in 0..16 {
        let name = format!("load-{i}");
        store.backend.create_profile(Some(name.clone())).await.unwrap();
        writers.push(name);
    }
    let from = counter.now().await;
    let started = Instant::now();
    let mut tasks = Vec::new();
    for name in &writers {
        let backend = store.backend.clone();
        let name = name.clone();
        tasks.push(tokio::spawn(async move {
            for round in 0..25 {
                let mut session = backend.session(Some(name.clone()), true).unwrap();
                insert(&mut session, &format!("load-{round}")).await.unwrap();
                session.close(true).await.unwrap();
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let elapsed = started.elapsed();
    let (s, w) = counter.since(from).await;
    eprintln!(
        "16 tenants x 25 writing transactions: {elapsed:?}, {:.0} commits/s, {s} store \
         statements, {w} witness queries",
        400.0 / elapsed.as_secs_f64()
    );
    store.assert_agreement().await;

    // A store that is not bound pays no more than before the fence changed.
    let (plain_name, plain) = freshness_support::unbound_store(&base).await;
    let plain_profile = plain.get_active_profile();
    seed(&plain, &plain_profile, "row").await;
    for _ in 0..3 {
        let mut session = plain.session(None, false).unwrap();
        assert!(fetch(&mut session, "row").await.unwrap());
        session.close(false).await.unwrap();
    }
    let unbound = Counter {
        pool: counter.pool.clone(),
        store: plain_name,
        witness: counter.witness.clone(),
    };
    let from = unbound.now().await;
    for _ in 0..ROUNDS {
        let mut session = plain.session(None, false).unwrap();
        assert!(fetch(&mut session, "row").await.unwrap());
        session.close(false).await.unwrap();
    }
    let (s, w) = unbound.since(from).await;
    check("unbound plain fetch, store statements", s as f64 / ROUNDS as f64, 3.0);
    check("unbound plain fetch, witness queries", w as f64, 0.0);
    let from = unbound.now().await;
    for round in 0..ROUNDS {
        let mut session = plain.session(None, true).unwrap();
        for _ in 0..READS {
            assert!(fetch(&mut session, "row").await.unwrap());
        }
        insert(&mut session, &format!("written-{round}")).await.unwrap();
        session.close(true).await.unwrap();
    }
    let (s, w) = unbound.since(from).await;
    check(
        "unbound transaction with 5 reads and 1 write, store statements",
        s as f64 / ROUNDS as f64,
        (4 + READS) as f64,
    );
    check("unbound transaction, witness queries", w as f64, 0.0);
    plain.close().await.unwrap();

    // Cold lease: 200 concurrent plain reads share the witness check.
    let cold = bound_store(&base, "&freshness_read_lease_ms=1500").await;
    seed(&cold.backend, &cold.backend.get_active_profile(), "row").await;
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let from = counter.now().await;
    let mut tasks = Vec::new();
    for _ in 0..200 {
        let backend = cold.backend.clone();
        tasks.push(tokio::spawn(async move {
            let mut session = backend.session(None, false).unwrap();
            let found = fetch(&mut session, "row").await;
            session.close(false).await.unwrap();
            found
        }));
    }
    let mut refused = 0;
    for task in tasks {
        if !matches!(task.await.unwrap(), Ok(true)) {
            refused += 1;
        }
    }
    let (_, w) = counter.since(from).await;
    check("200 concurrent cold reads, witness queries", w as f64, 10.0);
    check("200 concurrent cold reads, refused", refused as f64, 0.0);

    // A committer that cannot take the head row gives up in bounded time, before the witness.
    let before = store.assert_agreement().await;
    let side = admin(&store.store_url).await;
    let mut hold = side.begin().await.unwrap();
    sqlx::query("SELECT value FROM config WHERE name = 'askar_freshness_head_v1' FOR UPDATE")
        .fetch_one(&mut *hold)
        .await
        .unwrap();
    let started = Instant::now();
    let blocked = tokio::time::timeout(Duration::from_secs(4), async {
        let mut session = store.backend.session(Some(tenant.clone()), true).unwrap();
        insert(&mut session, "behind-the-head-lock").await?;
        session.close(true).await
    })
    .await;
    let waited = started.elapsed();
    hold.rollback().await.unwrap();
    side.close().await;
    match blocked {
        Ok(Err(error)) => eprintln!("blocked committer refused after {waited:?}: {error}"),
        Ok(Ok(())) => failures.push("a committer behind a held head row committed".into()),
        Err(_) => failures.push(format!(
            "a committer behind a held head row was still waiting after {waited:?}"
        )),
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    if store.witness_head().await.0 != before {
        failures.push("the blocked committer advanced the witness".into());
    }
    let reopened = open(&store.pinned, &store.key).await.expect("the store still opens");
    seed(&reopened, &tenant, "after-the-blocked-commit").await;
    assert_eq!(store.assert_agreement().await, before + 1);

    assert!(failures.is_empty(), "budgets exceeded:\n{}", failures.join("\n"));
}
