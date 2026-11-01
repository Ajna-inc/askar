//! Deterministic live-writer/read races. The synchronization exists only in tests.
use super::Head;
use std::sync::{Mutex, OnceLock};
use tokio::sync::oneshot;

struct Pause {
    lineage: uuid::Uuid,
    skip: usize,
    arrived: oneshot::Sender<()>,
    resume: oneshot::Receiver<()>,
}
static PAUSE: OnceLock<Mutex<Option<Pause>>> = OnceLock::new();

pub(super) async fn pause(head: &Head) {
    let paused = {
        let mut guard = PAUSE.get_or_init(|| Mutex::new(None)).lock().unwrap();
        match guard.as_mut() {
            Some(p) if p.lineage == head.lineage && p.skip == 0 => guard.take(),
            Some(p) if p.lineage == head.lineage => {
                p.skip -= 1;
                None
            }
            _ => None,
        }
    };
    if let Some(p) = paused {
        let _ = p.arrived.send(());
        let _ = p.resume.await;
    }
}

/// The next `n` compare-and-advance statements from this head reach the witness and their
/// answers are lost: what a deadline that fires after the statement was sent looks like.
static LOSE_ADVANCE: Mutex<Vec<(Head, u32)>> = Mutex::new(Vec::new());

fn lose_advance_answers(previous: &Head, count: u32) {
    LOSE_ADVANCE.lock().unwrap().push((previous.clone(), count));
}

pub(super) fn lose_advance_answer(previous: &Head) -> bool {
    let mut guard = LOSE_ADVANCE.lock().unwrap();
    let Some(at) = guard.iter().position(|(head, _)| head == previous) else {
        return false;
    };
    guard[at].1 -= 1;
    if guard[at].1 == 0 {
        guard.remove(at);
    }
    true
}

/// No attempt of a commit's compare-and-advance is answered, and the first one did apply:
/// the witness is one ahead of a store whose transaction was rolled back. The next commit of
/// the same process completes that very advance instead of being refused as stale.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ASKAR_FRESHNESS_WITNESS_URL and ASKAR_READ_RACE_STORE_URL (disposable Postgres)"]
async fn an_unanswered_advance_is_completed_by_the_next_commit() {
    use crate::{
        backend::{postgres::PostgresStoreOptions, Backend, BackendSession, db_utils::ExtDatabase},
        entry::{EntryKind, EntryOperation},
        protect::{generate_raw_store_key, StoreKeyMethod},
    };
    let witness = super::PostgresWitness::connect(
        &std::env::var("ASKAR_FRESHNESS_WITNESS_URL").expect("disposable witness URI"),
    )
    .await
    .unwrap();
    witness.provision().await.unwrap();
    let mut uri = url::Url::parse(
        &std::env::var("ASKAR_READ_RACE_STORE_URL").expect("disposable local-store URI"),
    )
    .unwrap();
    uri.set_path(&format!("unanswered_{}", uuid::Uuid::new_v4().simple()));
    let key = generate_raw_store_key(None).unwrap();
    let backend = PostgresStoreOptions::new(uri.as_str())
        .unwrap()
        .provision(StoreKeyMethod::RawKey, key.as_ref(), None, false)
        .await
        .unwrap();
    let head = backend.bind_freshness(&witness).await.unwrap();
    let write = |name: &'static str| {
        let mut session = backend.session(None, true).unwrap();
        async move {
            session
                .update(EntryKind::Item, EntryOperation::Insert, "c", name, Some(b"v"), None, None)
                .await?;
            session.close(true).await
        }
    };
    lose_advance_answers(&head, super::ADVANCE_ATTEMPTS);
    let lost = write("lost").await.unwrap_err();
    assert!(lost.message().unwrap().contains("outcome unresolved"), "{lost}");
    // The witness holds the advance nobody was told about; the store's head did not move.
    assert!(witness.check(&head).await.unwrap_err().read_head_moved);

    write("kept").await.expect("the next commit completes the unanswered advance");
    let pool = sqlx::PgPool::connect(uri.as_str()).await.unwrap();
    let mut conn = pool.acquire().await.unwrap();
    let local = <sqlx::Postgres as ExtDatabase>::freshness_head(&mut conn, false)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(local.sequence, head.sequence + 1);
    witness.check(&local).await.unwrap();
    let mut session = backend.session(None, false).unwrap();
    assert!(session.fetch(EntryKind::Item, "c", "kept", false).await.unwrap().is_some());
    assert!(session.fetch(EntryKind::Item, "c", "lost", false).await.unwrap().is_none());
    backend.close().await.unwrap();
}

/// A compare-and-advance whose answer never arrives is asked again, not assumed failed: the
/// witness holds the new head, so the commit goes on; a store that is really stale is refused
/// and nothing was advanced on its behalf.
#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires independent disposable witness in ASKAR_FRESHNESS_WITNESS_URL"]
async fn an_advance_with_a_lost_answer_resolves_to_what_the_witness_holds() {
    let witness = super::PostgresWitness::connect(
        &std::env::var("ASKAR_FRESHNESS_WITNESS_URL").expect("disposable witness URI"),
    )
    .await
    .unwrap();
    witness.provision().await.unwrap();
    let head = Head::initial();
    witness.register(&head).await.unwrap();
    let next = head.next().unwrap();
    lose_advance_answers(&head, 1);
    // Applied, answer lost, asked again: nothing changes, the witness holds `next`.
    assert_eq!(
        witness.advance_resolved(&head, &next).await.unwrap(),
        super::Advance::Applied
    );
    witness.check(&next).await.unwrap();
    // Asked from a head the witness no longer holds, to a head it does not hold: refused.
    let fork = head.next().unwrap();
    assert_eq!(
        witness.advance_resolved(&head, &fork).await.unwrap(),
        super::Advance::Refused
    );
    witness.check(&next).await.unwrap();
    // The single attempt of the public operation still reports the lost answer as unknown.
    let after = next.next().unwrap();
    lose_advance_answers(&next, 1);
    assert!(witness.advance(&next, &after).await.is_err());
    witness.check(&after).await.unwrap();
}

#[cfg(all(feature = "sqlite", feature = "postgres"))]
#[tokio::test]
#[ignore = "requires independent disposable witness in ASKAR_FRESHNESS_WITNESS_URL"]
async fn live_reads_restart_entire_operation_after_confirmed_head_movement() {
    use crate::{
        backend::{sqlite::SqliteStoreOptions, Backend, BackendSession},
        entry::{EntryKind, EntryOperation},
        protect::{generate_raw_store_key, StoreKeyMethod},
    };
    use std::sync::Arc;
    let witness = super::PostgresWitness::connect(
        &std::env::var("ASKAR_FRESHNESS_WITNESS_URL").expect("disposable witness URI"),
    )
    .await
    .unwrap();
    witness.provision().await.unwrap();
    for (operation, skip) in [
        ("fetch", 0),
        ("fetch", 2),
        ("count", 2),
        ("page", 2),
        ("page", 4),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let uri = format!("sqlite://{}", dir.path().join("read.db").display());
        let key = generate_raw_store_key(None).unwrap();
        let backend = Arc::new(
            SqliteStoreOptions::new(uri.as_str())
                .unwrap()
                .provision(StoreKeyMethod::RawKey, key.as_ref(), None, false)
                .await
                .unwrap(),
        );
        let head = backend.bind_freshness(&witness).await.unwrap();
        // These cases place a commit at one exact witness check of the read; with a read
        // lease the read is admitted without those checks.
        super::set_read_lease(head.lineage, Some(std::time::Duration::ZERO));
        read_case(backend, head.lineage, operation, skip).await;
    }
    // A live clone opened before advancement cannot use retries to authorize its
    // older snapshot. Copy only a closed, quiescent SQLite file (no WAL loss).
    let dir = tempfile::tempdir().unwrap();
    let current_path = dir.path().join("current.db");
    let clone_path = dir.path().join("clone.db");
    let uri = format!("sqlite://{}", current_path.display());
    let clone_uri = format!("sqlite://{}", clone_path.display());
    let key = generate_raw_store_key(None).unwrap();
    let current = SqliteStoreOptions::new(uri.as_str())
        .unwrap()
        .provision(StoreKeyMethod::RawKey, key.as_ref(), None, false)
        .await
        .unwrap();
    let head = current.bind_freshness(&witness).await.unwrap();
    super::set_read_lease(head.lineage, Some(std::time::Duration::ZERO));
    current.close().await.unwrap();
    std::fs::copy(&current_path, &clone_path).unwrap();
    let current = SqliteStoreOptions::new(uri.as_str())
        .unwrap()
        .open(None, key.as_ref(), None)
        .await
        .unwrap();
    let old_clone = SqliteStoreOptions::new(clone_uri.as_str())
        .unwrap()
        .open(None, key.as_ref(), None)
        .await
        .unwrap();
    let mut old_reader = old_clone.session(None, false).unwrap();
    assert!(old_reader
        .fetch(EntryKind::Item, "race", "a", false)
        .await
        .unwrap()
        .is_none());
    let mut writer = current.session(None, false).unwrap();
    writer
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            "race",
            "a",
            Some(b"current"),
            None,
            None,
        )
        .await
        .unwrap();
    assert!(old_reader
        .fetch(EntryKind::Item, "race", "a", false)
        .await
        .is_err());
    assert!(old_reader
        .count(Some(EntryKind::Item), Some("race"), None)
        .await
        .is_err());
    assert!(old_reader
        .fetch_all(
            Some(EntryKind::Item),
            Some("race"),
            None,
            None,
            None,
            false,
            false
        )
        .await
        .is_err());
    assert!(SqliteStoreOptions::new(clone_uri.as_str())
        .unwrap()
        .open(None, key.as_ref(), None)
        .await
        .is_err());
    // Missing witness state is terminal; neither absence nor an unknown outcome
    // may be classified as a confirmed movement eligible for another attempt.
    sqlx::query("DELETE FROM askar_freshness_witness_v1 WHERE lineage=$1")
        .bind(head.lineage.to_string())
        .execute(&witness.pool)
        .await
        .unwrap();
    let missing = witness.check(&head).await.unwrap_err();
    assert!(missing.message().unwrap().contains("missing witness"));
    assert!(!missing.read_head_moved);
    let mut retry = super::ReadRetry::new(false);
    assert!(!retry.again(&missing).await);
    assert!(
        !retry
            .again(&err_msg!(Backend, "Freshness witness unavailable"))
            .await
    );
    // Neither equal/lower sequence forks nor malformed witness state is a
    // confirmed forward movement. Never retry these refusals.
    for (sequence, token) in [
        (head.sequence.to_string(), uuid::Uuid::new_v4().to_string()),
        (
            "not-a-sequence".to_string(),
            uuid::Uuid::new_v4().to_string(),
        ),
        (
            (head.sequence + 1).to_string(),
            uuid::Uuid::nil().to_string(),
        ),
        ((head.sequence + 1).to_string(), "not-a-token".to_string()),
        (
            format!("0{}", head.sequence + 1),
            uuid::Uuid::new_v4().to_string(),
        ),
    ] {
        sqlx::query(
            "INSERT INTO askar_freshness_witness_v1(lineage,sequence,token) VALUES ($1,$2,$3)",
        )
        .bind(head.lineage.to_string())
        .bind(sequence)
        .bind(token)
        .execute(&witness.pool)
        .await
        .unwrap();
        assert!(!witness.check(&head).await.unwrap_err().read_head_moved);
        sqlx::query("DELETE FROM askar_freshness_witness_v1 WHERE lineage=$1")
            .bind(head.lineage.to_string())
            .execute(&witness.pool)
            .await
            .unwrap();
    }

    writer.close(false).await.unwrap();
    old_reader.close(false).await.unwrap();
    old_clone.close().await.unwrap();
    current.close().await.unwrap();
    postgres_live_reads_restart_entire_operation_after_confirmed_head_movement().await;
}

#[cfg(all(feature = "sqlite", feature = "postgres"))]
async fn read_case<B: crate::backend::Backend + 'static>(
    backend: std::sync::Arc<B>,
    lineage: uuid::Uuid,
    operation: &'static str,
    skip: usize,
) {
    use crate::{
        backend::BackendSession,
        entry::{EntryKind, EntryOperation},
    };
    let mut writer = backend.session(None, false).unwrap();
    writer
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            "race",
            "a",
            Some(b"old"),
            None,
            None,
        )
        .await
        .unwrap();
    if operation == "page" {
        for i in 0..34 {
            writer
                .update(
                    EntryKind::Item,
                    EntryOperation::Insert,
                    "race",
                    &format!("z{i:02}"),
                    Some(b"stable"),
                    None,
                    None,
                )
                .await
                .unwrap();
        }
    }
    let (arrived, waiting) = oneshot::channel();
    let (resume, resumed) = oneshot::channel();
    *PAUSE.get().unwrap().lock().unwrap() = Some(Pause {
        lineage,
        skip,
        arrived,
        resume: resumed,
    });
    let reader = tokio::spawn({
        let backend = backend.clone();
        async move {
            let mut reader = backend.session(None, false).unwrap();
            match operation {
                "fetch" => {
                    let item = reader.fetch(EntryKind::Item, "race", "a", false).await?;
                    assert_eq!(item.unwrap().value.as_ref(), b"new");
                }
                "count" => assert_eq!(
                    reader
                        .count(Some(EntryKind::Item), Some("race"), None)
                        .await?,
                    2
                ),
                "page" => {
                    let rows = reader
                        .fetch_all(
                            Some(EntryKind::Item),
                            Some("race"),
                            None,
                            None,
                            None,
                            false,
                            false,
                        )
                        .await?;
                    assert_eq!(rows.len(), 36);
                    assert_eq!(
                        rows.iter().find(|r| r.name == "a").unwrap().value.as_ref(),
                        b"new"
                    );
                }
                _ => unreachable!(),
            }
            Ok::<_, crate::Error>(())
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap();
    writer
        .update(
            EntryKind::Item,
            EntryOperation::Replace,
            "race",
            "a",
            Some(b"new"),
            None,
            None,
        )
        .await
        .unwrap();
    writer
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            "race",
            "added",
            Some(b"new"),
            None,
            None,
        )
        .await
        .unwrap();
    resume.send(()).unwrap();
    reader
        .await
        .unwrap()
        .expect("a live store must restart the full read, not expose stale results");
    writer.close(false).await.unwrap();
    backend.close().await.unwrap();
}

#[cfg(all(feature = "sqlite", feature = "postgres"))]
async fn postgres_live_reads_restart_entire_operation_after_confirmed_head_movement() {
    use crate::{
        backend::postgres::PostgresStoreOptions,
        protect::{generate_raw_store_key, StoreKeyMethod},
    };
    let witness = super::PostgresWitness::connect(
        &std::env::var("ASKAR_FRESHNESS_WITNESS_URL").expect("disposable witness URI"),
    )
    .await
    .unwrap();
    witness.provision().await.unwrap();
    for (operation, skip) in [
        ("fetch", 0),
        ("fetch", 2),
        ("count", 2),
        ("page", 2),
        ("page", 4),
    ] {
        let mut uri = url::Url::parse(
            &std::env::var("ASKAR_READ_RACE_STORE_URL").expect("disposable local-store URI"),
        )
        .unwrap();
        uri.set_path(&format!("read_race_{}", uuid::Uuid::new_v4().simple()));
        let key = generate_raw_store_key(None).unwrap();
        let backend = std::sync::Arc::new(
            PostgresStoreOptions::new(uri.as_str())
                .unwrap()
                .provision(StoreKeyMethod::RawKey, key.as_ref(), None, false)
                .await
                .unwrap(),
        );
        let head = backend.bind_freshness(&witness).await.unwrap();
        // These cases place a commit at one exact witness check of the read; with a read
        // lease the read is admitted without those checks.
        super::set_read_lease(head.lineage, Some(std::time::Duration::ZERO));
        read_case(backend, head.lineage, operation, skip).await;
    }
}

#[tokio::test(start_paused = true)]
async fn retry_budget_is_bounded_and_never_authorizes_unknown_state() {
    let mut moved = err_msg!(Backend, "Store freshness refused: stale or missing witness");
    moved.read_head_moved = true;
    // A confirmed forward head is repeated for the whole budget, 10 ms apart, and then refused:
    // long enough for a live writer's durable commit, bounded for a stale clone.
    let started = tokio::time::Instant::now();
    let mut retry = super::ReadRetry::new(false);
    let mut attempts = 0u32;
    while retry.again(&moved).await {
        attempts += 1;
        assert!(attempts <= 1_000, "the retry budget is not bounded");
    }
    let waited = started.elapsed();
    assert!(waited >= super::READ_RACE_BUDGET, "gave up after {waited:?}");
    assert!(
        waited < super::READ_RACE_BUDGET + std::time::Duration::from_millis(20),
        "kept going past the budget: {waited:?}"
    );
    assert!(attempts >= 100, "{attempts} attempts in {waited:?}");
    assert!(!retry.again(&moved).await);
    let mut transaction = super::ReadRetry::new(true);
    assert!(!transaction.again(&moved).await);
    let mut unknown = super::ReadRetry::new(false);
    assert!(
        !unknown
            .again(&err_msg!(Backend, "Freshness witness unavailable"))
            .await
    );
    assert!(
        !unknown
            .again(&err_msg!(
                Backend,
                "Store freshness binding absent or mismatched"
            ))
            .await
    );
}

/// A bound session outside a transaction is admitted while a transaction on the same profile
/// holds the head (`FOR UPDATE`) and the profile row (`FOR NO KEY UPDATE`): its admission reads
/// the committed rows without row locks, so it never queues behind the transaction. The tenant
/// inbox unpacks inside its transaction while the unpack's secrets resolver reads the wallet from
/// another connection; a locking profile read there waited for that transaction until the
/// 30 s unpack timeout.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ASKAR_FRESHNESS_WITNESS_URL and ASKAR_READ_RACE_STORE_URL (disposable Postgres)"]
async fn a_bound_session_outside_a_transaction_never_waits_on_a_transactions_locks() {
    use crate::{
        backend::{postgres::PostgresStoreOptions, Backend, BackendSession},
        entry::{EntryKind, EntryOperation},
        protect::{generate_raw_store_key, StoreKeyMethod},
    };
    use std::time::Duration;
    let witness = super::PostgresWitness::connect(
        &std::env::var("ASKAR_FRESHNESS_WITNESS_URL").expect("disposable witness URI"),
    )
    .await
    .unwrap();
    witness.provision().await.unwrap();
    let mut uri = url::Url::parse(
        &std::env::var("ASKAR_READ_RACE_STORE_URL").expect("disposable local-store URI"),
    )
    .unwrap();
    uri.set_path(&format!("lock_race_{}", uuid::Uuid::new_v4().simple()));
    let key = generate_raw_store_key(None).unwrap();
    let backend = PostgresStoreOptions::new(uri.as_str())
        .unwrap()
        .provision(StoreKeyMethod::RawKey, key.as_ref(), None, false)
        .await
        .unwrap();
    backend.bind_freshness(&witness).await.unwrap();

    let mut writer = backend.session(None, false).unwrap();
    writer
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            "lock",
            "row",
            Some(b"committed"),
            None,
            None,
        )
        .await
        .unwrap();
    writer.close(false).await.unwrap();

    // Admission of a transaction locks the head and the profile row until it settles.
    let mut holder = backend.session(None, true).unwrap();
    assert!(holder
        .fetch(EntryKind::Item, "lock", "row", false)
        .await
        .unwrap()
        .is_some());

    let mut reader = backend.session(None, false).unwrap();
    let started = tokio::time::Instant::now();
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        reader.fetch(EntryKind::Item, "lock", "row", false),
    )
    .await;
    let waited = started.elapsed();
    let entry = read
        .unwrap_or_else(|_| {
            panic!("a bound session outside a transaction waited {waited:?} on a transaction's row locks")
        })
        .unwrap()
        .expect("the committed row");
    assert_eq!(entry.value.as_ref(), b"committed");

    // The transaction still owns its locks and commits as usual afterwards.
    holder
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            "lock",
            "later",
            Some(b"after"),
            None,
            None,
        )
        .await
        .unwrap();
    holder.close(true).await.unwrap();
    reader.close(false).await.unwrap();
    backend.close().await.unwrap();
}
