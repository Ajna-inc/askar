//! The commit of a transaction that wrote to a witness-bound store.
//!
//! The store keeps one freshness head. It is locked only here, by a commit that wrote, from
//! the moment the head is read under the lock until the local COMMIT that makes its successor
//! visible: a few statements, never the caller's work. Read-only transactions, rollbacks and
//! every read never take it.
//!
//! Commits that wait at the same time share one advance. One of them, the leader, takes the
//! head lock inside its own transaction, writes the next head there and advances the witness
//! once; the others, the followers, then commit their own transactions, all at once; the
//! leader commits last. Three orderings carry the property:
//!
//! 1. The witness is advanced before any local COMMIT of the batch: a copy of the store that
//!    lacks an acknowledged write has a head behind the witness.
//! 2. The leader's COMMIT, which makes the new head visible, comes after every follower's
//!    COMMIT has settled: a copy that shows the new head holds every write acknowledged
//!    under it.
//! 3. Nobody is told its commit succeeded before the leader's COMMIT has been attempted.
//!
//! The batch runs on its own task and owns the connections of its transactions until every
//! outcome is known. A caller that stops waiting (a timeout around the transaction, a dropped
//! request) therefore cannot stop a commit between the witness advance and the local COMMIT.
//!
//! Commits of other processes on the same database wait on the head row lock and chain.
use std::{
    collections::VecDeque,
    fmt::{self, Debug, Formatter},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::Poll,
    time::Duration,
};

use sqlx::{pool::PoolConnection, Database, TransactionManager};
use tokio::sync::oneshot;

use super::{
    db_recovery::recover,
    db_utils::ExtDatabase,
    freshness::{self, Advance, Head, Lineage},
};
use crate::error::Error;

/// Longest a local COMMIT may take once the witness has been advanced.
const COMMIT_WAIT: Duration = Duration::from_secs(30);
/// Most transactions under one head advance.
const MAX_BATCH: usize = 256;

/// How long a commit waits for the head row before it gives up, having changed nothing:
/// `ASKAR_FRESHNESS_COMMIT_LOCK_WAIT_MS`, default 10 s.
fn lock_wait() -> Duration {
    Duration::from_millis(
        std::env::var("ASKAR_FRESHNESS_COMMIT_LOCK_WAIT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(10_000),
    )
}

/// `ASKAR_FRESHNESS_GROUP_COMMIT=0` gives every commit its own advance.
fn group_commit() -> bool {
    std::env::var("ASKAR_FRESHNESS_GROUP_COMMIT").as_deref() != Ok("0")
}

/// The connection is handed back only for an implicit transaction of a session that goes on.
type Settled<DB> = Result<Option<PoolConnection<DB>>, Error>;

struct Waiter<DB: ExtDatabase> {
    conn: Option<PoolConnection<DB>>,
    admitted: Head,
    expected: Option<uuid::Uuid>,
    keep: bool,
    reply: Option<oneshot::Sender<Settled<DB>>>,
}

impl<DB: ExtDatabase> Waiter<DB> {
    fn conn(&mut self) -> &mut DB::Connection {
        self.conn.as_mut().expect("the waiter's connection")
    }

    /// The transaction did not commit, or may not have: its connection is rolled back and
    /// repaired off the pool, never returned to it as it is.
    fn fail(mut self, error: Error) {
        if let Some(conn) = self.conn.take() {
            recover(conn);
        }
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(Err(error));
        }
    }

    async fn settle(mut self, committed: Result<(), Error>) {
        if let Err(error) = committed {
            return self.fail(error);
        }
        let mut conn = self.conn.take().expect("the waiter's connection");
        let reply = self.reply.take().expect("the waiter's reply");
        if self.keep {
            // A caller that is gone drops the clean connection back into the pool.
            let _ = reply.send(Ok(Some(conn)));
        } else {
            conn.return_to_pool().await;
            let _ = reply.send(Ok(None));
        }
    }
}

impl<DB: ExtDatabase> Drop for Waiter<DB> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            recover(conn);
        }
    }
}

struct State<DB: ExtDatabase> {
    waiting: VecDeque<Waiter<DB>>,
    running: bool,
}

struct Queue<DB: ExtDatabase> {
    state: Mutex<State<DB>>,
}

impl<DB: ExtDatabase> Queue<DB> {
    fn state(&self) -> std::sync::MutexGuard<'_, State<DB>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One per backend: the queue of its commits that must advance the head.
pub(crate) struct Committer<DB: ExtDatabase> {
    queue: Arc<Queue<DB>>,
}

impl<DB: ExtDatabase> Clone for Committer<DB> {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
        }
    }
}

impl<DB: ExtDatabase> Default for Committer<DB> {
    fn default() -> Self {
        Self {
            queue: Arc::new(Queue {
                state: Mutex::new(State {
                    waiting: VecDeque::new(),
                    running: false,
                }),
            }),
        }
    }
}

impl<DB: ExtDatabase> Debug for Committer<DB> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("Committer")
    }
}

impl<DB: ExtDatabase> Committer<DB> {
    /// Commit the open transaction on `conn`, which wrote, on a store admitted at `admitted`.
    pub(crate) async fn commit(
        &self,
        conn: PoolConnection<DB>,
        admitted: Head,
        expected: Option<uuid::Uuid>,
        keep: bool,
    ) -> Settled<DB> {
        let (reply, settled) = oneshot::channel();
        // Nothing awaits between taking the connection and queueing it.
        let start = {
            let mut state = self.queue.state();
            state.waiting.push_back(Waiter {
                conn: Some(conn),
                admitted,
                expected,
                keep,
                reply: Some(reply),
            });
            !std::mem::replace(&mut state.running, true)
        };
        if start {
            // On the crate's own runtime, never the caller's: a caller's runtime may be a
            // short-lived or single-threaded one that stops being driven once its own commit
            // is answered, while this runner is serving the next batch.
            crate::future::spawn_ok(run(self.queue.clone()));
        }
        settled
            .await
            .unwrap_or_else(|_| Err(err_msg!(Backend, "Freshness commit outcome unresolved")))
    }
}

/// Clears the queue's `running` mark if the runner is dropped (its runtime shut down).
struct Running<DB: ExtDatabase> {
    queue: Arc<Queue<DB>>,
    armed: bool,
}

impl<DB: ExtDatabase> Drop for Running<DB> {
    fn drop(&mut self) {
        if self.armed {
            let abandoned = {
                let mut state = self.queue.state();
                state.running = false;
                std::mem::take(&mut state.waiting)
            };
            drop(abandoned);
        }
    }
}

async fn run<DB: ExtDatabase>(queue: Arc<Queue<DB>>) {
    let mut running = Running {
        queue: queue.clone(),
        armed: true,
    };
    loop {
        let batch = {
            let mut state = queue.state();
            if state.waiting.is_empty() {
                state.running = false;
                running.armed = false;
                return;
            }
            let take = if group_commit() {
                state.waiting.len().min(MAX_BATCH)
            } else {
                1
            };
            state.waiting.drain(..take).collect::<VecDeque<_>>()
        };
        settle(batch).await;
    }
}

enum Refusal {
    /// The head could not be taken: no transaction of the batch can commit now.
    Head(&'static str),
    /// This transaction cannot lead; another one of the batch may.
    Own(Error),
}

/// Lock the head in the leader's transaction, check it continues what the leader was admitted
/// on, and write its successor there. Nothing outside this database has changed yet.
async fn lead<DB: ExtDatabase>(leader: &mut Waiter<DB>) -> Result<(Head, Head), Refusal> {
    let locked = tokio::time::timeout(lock_wait(), DB::freshness_head(leader.conn(), true))
        .await
        .map_err(|_| Refusal::Head("Freshness head busy: commit lock wait exceeded"))?
        .map_err(Refusal::Own)?;
    let previous = locked.ok_or_else(|| {
        Refusal::Own(err_msg!(
            Backend,
            "Store freshness binding absent or mismatched"
        ))
    })?;
    freshness::continues(&leader.admitted, &previous, leader.expected).map_err(Refusal::Own)?;
    // An earlier advance from this very head that the witness never answered is made again,
    // with the same token: no transaction committed under it (the head is still `previous`),
    // and the witness then holds this head whichever of the statements it applies.
    let next = match Lineage::of(previous.lineage).unanswered_from(&previous) {
        Some(next) => next,
        None => previous.next().map_err(Refusal::Own)?,
    };
    tokio::time::timeout(lock_wait(), DB::freshness_advance(leader.conn(), &next))
        .await
        .map_err(|_| Refusal::Own(err_msg!(Backend, "Freshness head write unanswered")))?
        .map_err(Refusal::Own)?;
    Ok((previous, next))
}

async fn commit_local<DB: ExtDatabase>(conn: &mut DB::Connection) -> Result<(), Error> {
    match tokio::time::timeout(COMMIT_WAIT, <DB as Database>::TransactionManager::commit(conn))
        .await
    {
        Ok(result) => result.map_err(err_map!(Backend, "Error committing transaction")),
        Err(_) => Err(err_msg!(
            Backend,
            "Error committing transaction: no acknowledgement"
        )),
    }
}

fn like(error: &Error) -> Error {
    Error::from_msg(error.kind(), error.to_string())
}

async fn settle<DB: ExtDatabase>(mut batch: VecDeque<Waiter<DB>>) {
    let (mut leader, previous, next) = loop {
        let Some(mut leader) = batch.pop_front() else {
            return;
        };
        match lead(&mut leader).await {
            Ok((previous, next)) => break (leader, previous, next),
            Err(Refusal::Head(message)) => {
                leader.fail(err_msg!(Backend, "{message}"));
                for waiter in batch {
                    waiter.fail(err_msg!(Backend, "{message}"));
                }
                return;
            }
            Err(Refusal::Own(error)) => leader.fail(error),
        }
    };
    let mut followers = Vec::with_capacity(batch.len());
    for waiter in batch {
        match freshness::continues(&waiter.admitted, &previous, waiter.expected) {
            Ok(()) => followers.push(waiter),
            Err(error) => waiter.fail(error),
        }
    }

    let lineage = Lineage::of(previous.lineage);
    // The witness is known to hold `previous` no later than now.
    let asked = tokio::time::Instant::now();
    let advanced = match freshness::witness().await {
        Ok(witness) => witness.advance_resolved(&previous, &next).await,
        Err(error) => Err(error),
    };
    let refused = match advanced {
        Ok(Advance::Applied) => None,
        // This store is stale or forked. Nothing was advanced.
        Ok(Advance::Refused) => {
            lineage.unanswered(None);
            Some(err_msg!(Backend, "Freshness advance refused: stale store"))
        }
        // The witness may hold `next`. Remembered: the next commit from `previous` makes
        // this same advance again (see `lead`).
        Ok(Advance::Unknown) => {
            lineage.unanswered(Some((&previous, &next)));
            Some(err_msg!(Backend, "Freshness witness outcome unresolved"))
        }
        Err(error) => Some(error),
    };
    if let Some(error) = refused {
        // No transaction of the batch commits. Every one is rolled back; the head lock goes
        // with the leader's.
        for waiter in followers {
            waiter.fail(like(&error));
        }
        leader.fail(error);
        return;
    }
    lineage.advanced(&previous, &next, asked);
    freshness::count_batch(1 + followers.len());

    let commits: Vec<Pin<Box<dyn Future<Output = Result<(), Error>> + Send + '_>>> = followers
        .iter_mut()
        .map(|waiter| Box::pin(commit_local::<DB>(waiter.conn())) as _)
        .collect();
    let committed = join_all(commits).await;
    // Last: the head becomes visible only after every follower's COMMIT has settled.
    let led = commit_local::<DB>(leader.conn()).await;
    match &led {
        Ok(()) => lineage.committed(&previous),
        // The witness is ahead of this store's head. Nothing rewinds it; the store is refused
        // from here on (see FRESHNESS.md, "When the witness is ahead").
        Err(_) => lineage.commit_failed(&previous),
    }
    for (waiter, committed) in followers.into_iter().zip(committed) {
        waiter.settle(committed).await;
    }
    leader.settle(led).await;
}

async fn join_all<T>(futures: Vec<Pin<Box<dyn Future<Output = T> + Send + '_>>>) -> Vec<T> {
    let mut pending: Vec<_> = futures.into_iter().map(Some).collect();
    let mut done: Vec<Option<T>> = pending.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut waiting = false;
        for (slot, out) in pending.iter_mut().zip(done.iter_mut()) {
            if let Some(future) = slot {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        *out = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => waiting = true,
                }
            }
        }
        if waiting {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    done.into_iter().map(|value| value.expect("joined")).collect()
}
