//! A new pooled SQLite connection must open while another writer holds the database.
//!
//! Every new connection used to run `PRAGMA journal_mode = WAL`, which needs an exclusive lock
//! that `busy_timeout` cannot wait for: opened while another connection held a write transaction,
//! it failed at once with "database is locked". Under load that failed inbound custody, rolled
//! back tenant transactions and answered authenticated requests 401.
#![cfg(feature = "sqlite")]

use askar_storage::{generate_raw_store_key, sqlite::SqliteStoreOptions, StoreKeyMethod};
use sqlx::Connection;
use std::time::Duration;

#[tokio::test]
async fn a_new_connection_opens_while_another_writer_holds_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let uri = format!("sqlite://{}", dir.path().join("store.db").display());
    let key = generate_raw_store_key(None).unwrap();
    let _store = SqliteStoreOptions::new(uri.as_str())
        .unwrap()
        .provision(StoreKeyMethod::RawKey, key.as_ref(), None, true)
        .await
        .expect("provision");

    // Another connection takes the write lock and keeps it briefly, as a busy runtime does.
    let mut writer = sqlx::SqliteConnection::connect(&uri).await.unwrap();
    // The file properties are still set, once, by provisioning.
    let auto_vacuum: i64 = sqlx::query_scalar("PRAGMA auto_vacuum").fetch_one(&mut writer).await.unwrap();
    let journal: String = sqlx::query_scalar("PRAGMA journal_mode").fetch_one(&mut writer).await.unwrap();
    assert_eq!((auto_vacuum, journal.as_str()), (2, "wal"), "incremental auto_vacuum and WAL");
    sqlx::query("BEGIN IMMEDIATE").execute(&mut writer).await.unwrap();
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        sqlx::query("COMMIT").execute(&mut writer).await.unwrap();
    });

    // A busy timeout shorter than the hold: opening must not need the lock at all.
    let opened = SqliteStoreOptions::new(format!("{uri}?busy_timeout=100").as_str())
        .unwrap()
        .open(Some(StoreKeyMethod::RawKey), key.as_ref(), None)
        .await;
    release.await.unwrap();
    assert!(opened.is_ok(), "a connection opened under a held write lock failed: {:?}", opened.err());
}
