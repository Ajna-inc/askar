//! Shared fixtures for the witness-bound PostgreSQL performance and safety tests.
//!
//! They run only with `AJNA_FRESHNESS_TEST_PG_URL` (a disposable PostgreSQL the tests may create
//! databases on, e.g. `postgres://postgres:pw@127.0.0.1:55461/postgres`) and are skipped
//! otherwise. Every test binary owns one witness database; every test owns one store database.
#![allow(dead_code)]

use askar_storage::{
    backend::{
        freshness::{Head, PostgresWitness},
        postgres::{PostgresBackend, PostgresStoreOptions},
    },
    entry::{EntryKind, EntryOperation},
    generate_raw_store_key, Backend, BackendSession, Error, PassKey, StoreKeyMethod,
};
use std::sync::Arc;

/// One witness database per test process: `ASKAR_FRESHNESS_WITNESS_URL` is process-wide.
static WITNESS: tokio::sync::Mutex<Option<String>> = tokio::sync::Mutex::const_new(None);

/// Every test of a binary runs on this one runtime: the witness pool is process-wide and its
/// connections live on the runtime that opened them.
pub fn run(test: impl std::future::Future<Output = ()>) {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(8)
                .enable_all()
                .build()
                .expect("a test runtime")
        })
        .block_on(test)
}

pub struct Bound {
    pub base: String,
    pub name: String,
    pub store_url: String,
    pub pinned: String,
    pub witness_url: String,
    pub witness: PostgresWitness,
    pub lineage: uuid::Uuid,
    pub key: PassKey<'static>,
    pub backend: Arc<PostgresBackend>,
}

pub fn base_url() -> Option<String> {
    match std::env::var("AJNA_FRESHNESS_TEST_PG_URL") {
        Ok(base) => Some(base),
        Err(_) => {
            eprintln!("skipped: AJNA_FRESHNESS_TEST_PG_URL is not set");
            None
        }
    }
}

pub async fn admin(url: &str) -> sqlx::PgPool {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(url)
        .await
        .expect("connect to the test cluster")
}

fn sibling(base: &str, name: &str) -> String {
    let (prefix, _) = base
        .rsplit_once('/')
        .expect("a PostgreSQL URL with a database path");
    format!("{prefix}/{name}")
}

async fn witness_url(base: &str) -> String {
    let mut guard = WITNESS.lock().await;
    if let Some(url) = guard.as_ref() {
        return url.clone();
    }
    let name = format!("witness_{}", uuid::Uuid::new_v4().simple());
    let pool = admin(base).await;
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&pool)
        .await
        .expect("create the witness database");
    pool.close().await;
    let url = format!("{}?sslmode=disable", sibling(base, &name));
    std::env::set_var("ASKAR_FRESHNESS_WITNESS_URL", &url);
    let witness = PostgresWitness::connect(&url)
        .await
        .expect("connect to the witness");
    witness.provision().await.expect("provision the witness");
    *guard = Some(url.clone());
    url
}

/// Options appended to the pinned store URL (`&key=value`).
pub async fn bound_store(base: &str, extra: &str) -> Bound {
    let witness_url = witness_url(base).await;
    let name = format!("store_{}", uuid::Uuid::new_v4().simple());
    let store_url = sibling(base, &name);
    let key = generate_raw_store_key(None).expect("a store key");
    let backend = PostgresStoreOptions::new(store_url.as_str())
        .expect("store options")
        .provision(StoreKeyMethod::RawKey, key.as_ref(), None, false)
        .await
        .expect("provision the store");
    let witness = PostgresWitness::connect(&witness_url)
        .await
        .expect("connect to the witness");
    let head = backend
        .bind_freshness(&witness)
        .await
        .expect("bind the store");
    backend.close().await.expect("close the provisioned store");
    let pinned = format!(
        "{store_url}?freshness_lineage={}&max_connections=64{extra}",
        head.lineage
    );
    let backend = open(&pinned, &key).await.expect("open the bound store");
    Bound {
        base: base.to_owned(),
        name,
        store_url,
        pinned,
        witness_url,
        witness,
        lineage: head.lineage,
        key,
        backend: Arc::new(backend),
    }
}

/// A store with no freshness binding: its database name and an open handle.
pub async fn unbound_store(base: &str) -> (String, PostgresBackend) {
    let name = format!("plain_{}", uuid::Uuid::new_v4().simple());
    let key = generate_raw_store_key(None).expect("a store key");
    let backend = PostgresStoreOptions::new(format!("{}?max_connections=16", sibling(base, &name)).as_str())
        .expect("store options")
        .provision(StoreKeyMethod::RawKey, key.as_ref(), None, false)
        .await
        .expect("provision the store");
    (name, backend)
}

pub async fn open(pinned: &str, key: &PassKey<'static>) -> Result<PostgresBackend, Error> {
    PostgresStoreOptions::new(pinned)?
        .open(None, key.as_ref(), None)
        .await
}

impl Bound {
    /// The committed local head, read beside the store.
    pub async fn local_head(&self) -> Head {
        let pool = admin(&self.store_url).await;
        let (value,): (String,) =
            sqlx::query_as("SELECT value FROM config WHERE name = 'askar_freshness_head_v1'")
                .fetch_one(&pool)
                .await
                .expect("read the local head");
        pool.close().await;
        serde_json::from_str(&value).expect("decode the local head")
    }

    /// The witness row for this store's lineage.
    pub async fn witness_head(&self) -> (u64, uuid::Uuid) {
        let pool = admin(&self.witness_url).await;
        let (sequence, token): (String, String) = sqlx::query_as(
            "SELECT sequence, token FROM askar_freshness_witness_v1 WHERE lineage = $1",
        )
        .bind(self.lineage.to_string())
        .fetch_one(&pool)
        .await
        .expect("read the witness head");
        pool.close().await;
        (sequence.parse().unwrap(), token.parse().unwrap())
    }

    /// Local head and witness agree; returns the sequence.
    pub async fn assert_agreement(&self) -> u64 {
        let local = self.local_head().await;
        let witness = self.witness_head().await;
        assert_eq!(
            (local.sequence, local.token),
            witness,
            "the local head and the witness disagree"
        );
        local.sequence
    }

    pub async fn profiles(&self, count: usize) -> Vec<String> {
        let mut names = Vec::new();
        for i in 0..count {
            let name = format!("tenant-{i}");
            self.backend
                .create_profile(Some(name.clone()))
                .await
                .expect("create a profile");
            names.push(name);
        }
        names
    }
}

pub async fn insert<S: BackendSession>(session: &mut S, name: &str) -> Result<(), Error> {
    session
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            "perf",
            name,
            Some(b"value"),
            None,
            None,
        )
        .await
}

pub async fn fetch<S: BackendSession>(session: &mut S, name: &str) -> Result<bool, Error> {
    Ok(session
        .fetch(EntryKind::Item, "perf", name, false)
        .await?
        .is_some())
}

/// One committed row on `profile`, through its own transaction.
pub async fn seed(backend: &PostgresBackend, profile: &str, name: &str) {
    let mut session = backend
        .session(Some(profile.to_owned()), true)
        .expect("a transaction");
    insert(&mut session, name).await.expect("seed a row");
    session.close(true).await.expect("commit the seed");
}
