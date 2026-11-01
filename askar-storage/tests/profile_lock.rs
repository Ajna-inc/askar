//! The profile row lock of a transaction, and the opt-in to share it.
//!
//! A transactional session locks its profile row `FOR NO KEY UPDATE` until it ends. That
//! keeps the profile from being removed under the transaction, and it also makes the
//! transactions of one profile run strictly one after another. A store opened with
//! `profile_lock=key_share` takes `FOR KEY SHARE` instead: removal is still held off, and the
//! profile's transactions run at the same time.
//!
//! Run with `AJNA_FRESHNESS_TEST_PG_URL` (see `freshness_support`); skipped otherwise.
#![cfg(feature = "postgres")]

mod freshness_support;

use askar_storage::{backend::postgres::PostgresBackend, Backend, BackendSession};
use freshness_support::{base_url, bound_store, fetch, insert, open};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// How long a second transaction on the same profile takes to write an unrelated row and
/// commit while the first one sleeps for 1.5 s between its write and its commit.
async fn second_writer_beside_a_sleeping_one(backend: Arc<PostgresBackend>) -> Duration {
    let profile = backend.get_active_profile();
    let slow = tokio::spawn({
        let backend = backend.clone();
        let profile = profile.clone();
        async move {
            let mut session = backend.session(Some(profile), true).unwrap();
            insert(&mut session, "slow").await.unwrap();
            tokio::time::sleep(Duration::from_millis(1500)).await;
            session.close(true).await.unwrap();
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    let mut session = backend.session(Some(profile.clone()), true).unwrap();
    insert(&mut session, "unrelated").await.unwrap();
    session.close(true).await.unwrap();
    let waited = started.elapsed();
    slow.await.unwrap();
    let mut session = backend.session(Some(profile), false).unwrap();
    assert!(fetch(&mut session, "slow").await.unwrap());
    assert!(fetch(&mut session, "unrelated").await.unwrap());
    waited
}

/// RED before the option existed: with `profile_lock=key_share` two transactions on ONE
/// profile do not wait for each other's unrelated writes.
#[test]
fn shared_profile_lock_lets_one_profiles_transactions_overlap() {
    freshness_support::run(async {
        let Some(base) = base_url() else { return };
        let store = bound_store(&base, "&profile_lock=key_share").await;
        let before = store.assert_agreement().await;
        let waited = second_writer_beside_a_sleeping_one(store.backend.clone()).await;
        assert!(
            waited < Duration::from_millis(500),
            "a transaction waited {waited:?} behind another transaction of its own profile"
        );
        assert_eq!(store.assert_agreement().await, before + 2);
    })
}

/// Guard: the default is unchanged. Transactions of one profile run one after another.
#[test]
fn default_profile_lock_serializes_one_profiles_transactions() {
    freshness_support::run(async {
        let Some(base) = base_url() else { return };
        let store = bound_store(&base, "").await;
        let waited = second_writer_beside_a_sleeping_one(store.backend.clone()).await;
        assert!(
            waited > Duration::from_millis(900),
            "the second transaction of a profile did not wait for the first: {waited:?}"
        );
        store.assert_agreement().await;
    })
}

/// Guard: a shared lock still keeps the profile from being removed under a transaction.
#[test]
fn shared_profile_lock_still_holds_off_removal() {
    freshness_support::run(async {
        let Some(base) = base_url() else { return };
        let store = bound_store(&base, "&profile_lock=key_share").await;
        let name = "held".to_string();
        store.backend.create_profile(Some(name.clone())).await.unwrap();
        let mut session = store.backend.session(Some(name.clone()), true).unwrap();
        insert(&mut session, "row").await.unwrap();

        let other = Arc::new(open(&store.pinned, &store.key).await.unwrap());
        let removal = tokio::spawn({
            let other = other.clone();
            let name = name.clone();
            async move { other.remove_profile(name).await }
        });
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(
            !removal.is_finished(),
            "the profile was removed under an open transaction"
        );
        // The transaction still works on its profile and commits.
        assert!(fetch(&mut session, "row").await.unwrap());
        session.close(true).await.unwrap();
        assert!(removal.await.unwrap().unwrap());
        store.assert_agreement().await;
    })
}
