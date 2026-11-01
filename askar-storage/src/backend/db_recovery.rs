//! Pooled connections whose transaction state became uncertain are repaired
//! before anyone else can use them, or discarded.
//!
//! sqlx tracks a transaction depth per connection and updates it only after
//! the database acknowledges BEGIN, COMMIT or ROLLBACK. A future dropped
//! between sending such a statement and its acknowledgement leaves that depth
//! (and, on SQLite, the worker's "ignore the next rollback" flag) out of step
//! with the database, yet sqlx still returns the connection to the pool. The
//! next BEGIN then becomes a SAVEPOINT (PostgreSQL) or is refused (SQLite),
//! or a later rollback is silently skipped.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use sqlx::{pool::PoolConnection, Connection, Database, TransactionManager};

use super::db_utils::ExtDatabase;

/// Longest a repair may wait for the database. A healthy ROLLBACK or ping
/// takes milliseconds; a silently dead peer would otherwise keep the
/// connection checked out until TCP gives up (AUD-A F11).
const REPAIR_WAIT: Duration = Duration::from_secs(15);

static REPAIRED: AtomicU64 = AtomicU64::new(0);
static DISCARDED: AtomicU64 = AtomicU64::new(0);

/// Process-wide counts of connections recovered after an interrupted
/// transaction command. A growing `discarded` count deserves attention.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryStats {
    /// Rolled back to a clean state and returned to the pool.
    pub repaired: u64,
    /// Closed because their state could not be restored.
    pub discarded: u64,
}

/// Read the recovery counters.
pub fn recovery_stats() -> RecoveryStats {
    RecoveryStats {
        repaired: REPAIRED.load(Ordering::Relaxed),
        discarded: DISCARDED.load(Ordering::Relaxed),
    }
}

type Tm<DB> = <DB as Database>::TransactionManager;

/// Bring sqlx's depth for `conn` to zero, rolling back what it still tracks.
pub(crate) async fn reset_depth<DB: ExtDatabase>(conn: &mut DB::Connection) -> bool {
    // SQLite: consumes an "ignore the next rollback" left by an
    // unacknowledged COMMIT/ROLLBACK, otherwise rolls back one level.
    // PostgreSQL: queues ROLLBACK for the depth sqlx still believes in.
    Tm::<DB>::start_rollback(conn);
    if conn.ping().await.is_err() {
        return false;
    }
    while Tm::<DB>::get_transaction_depth(conn) > 0 {
        if Tm::<DB>::rollback(conn).await.is_err() {
            return false;
        }
    }
    true
}

/// Take a connection in an unknown transaction state away from its session:
/// repair it in the background, then let it return to the pool or close.
pub(crate) fn recover<DB: ExtDatabase>(mut conn: PoolConnection<DB>) {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        DISCARDED.fetch_add(1, Ordering::Relaxed);
        conn.close_on_drop();
        return;
    };
    runtime.spawn(async move {
        let repaired = tokio::time::timeout(REPAIR_WAIT, DB::reset_connection(&mut *conn))
            .await
            .unwrap_or(false);
        if repaired {
            REPAIRED.fetch_add(1, Ordering::Relaxed);
            debug!("Repaired pooled connection after an interrupted transaction command");
        } else {
            DISCARDED.fetch_add(1, Ordering::Relaxed);
            warn!("Discarding pooled connection after an interrupted transaction command");
            conn.close_on_drop();
        }
    });
}

/// A pool connection that is recovered, not simply returned, unless settled.
pub(crate) struct Unsettled<DB: ExtDatabase>(Option<PoolConnection<DB>>);

impl<DB: ExtDatabase> Unsettled<DB> {
    pub(crate) fn new(conn: PoolConnection<DB>) -> Self {
        Self(Some(conn))
    }

    pub(crate) fn conn(&mut self) -> &mut DB::Connection {
        self.0.as_mut().expect("unsettled connection present")
    }

    pub(crate) fn settle(mut self) -> PoolConnection<DB> {
        self.0.take().expect("unsettled connection present")
    }
}

impl<DB: ExtDatabase> Drop for Unsettled<DB> {
    fn drop(&mut self) {
        if let Some(conn) = self.0.take() {
            recover(conn);
        }
    }
}
