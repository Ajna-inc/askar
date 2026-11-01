use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use sqlx::{
    pool::PoolConnection, Arguments, Database, Encode, Error as SqlxError, IntoArguments, Pool,
    TransactionManager, Type,
};

use crate::{
    entry::{EncEntryTag, Entry, EntryKind, EntryTag, TagFilter},
    error::Error,
    future::BoxFuture,
    protect::{EntryEncryptor, KeyCache, PassKey, ProfileId, ProfileKey, StoreKey, StoreKeyMethod},
    wql::{
        sql::TagSqlEncoder,
        tags::{tag_query, TagQueryEncoder},
    },
};

use super::{
    commit::Committer,
    db_recovery::{recover, reset_depth, Unsettled},
    freshness::{self, Head, ReadRetry},
    OrderBy,
};

/// cbindgen:ignore
pub const PAGE_SIZE: usize = 32;

pub type Expiry = chrono::DateTime<chrono::Utc>;

pub(crate) type Connection<DB> = <DB as Database>::Connection;

#[derive(Debug)]
pub(crate) enum DbSessionState<DB: ExtDatabase> {
    Active { conn: PoolConnection<DB> },
    Pending { pool: Pool<DB>, transaction: bool },
    Closed,
}

unsafe impl<DB: ExtDatabase> Sync for DbSessionState<DB> where DB::Connection: Send {}

/// In-process admission to a store's single writer.
///
/// SQLite admits one write transaction at a time, and `BEGIN IMMEDIATE` waits for it
/// (up to `busy_timeout`) on a pooled connection. Waiting there holds a pool slot the
/// whole time, so a few queued writers could take every connection while the writer
/// they wait for needed one more (any read on another session of the same store): it
/// then waited for a slot, they waited for it, and nothing moved until their
/// `busy_timeout` expired. A transaction therefore takes this gate before it takes a
/// connection: queued writers hold no connection, and the writer and every reader keep
/// the rest of the pool. The wait is bounded by the same `busy_timeout` and fails the
/// same way ("database is locked") as SQLite's own.
#[derive(Clone, Debug)]
pub(crate) struct WriteGate {
    permit: Arc<tokio::sync::Semaphore>,
    wait: std::time::Duration,
    waiting: Arc<std::sync::atomic::AtomicUsize>,
}

impl WriteGate {
    pub(crate) fn new(wait: std::time::Duration) -> Self {
        Self {
            permit: Arc::new(tokio::sync::Semaphore::new(1)),
            wait,
            waiting: Arc::default(),
        }
    }

    async fn admit(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Error> {
        use std::sync::atomic::Ordering;
        self.waiting.fetch_add(1, Ordering::AcqRel);
        let admitted = tokio::time::timeout(self.wait, self.permit.clone().acquire_owned()).await;
        self.waiting.fetch_sub(1, Ordering::AcqRel);
        match admitted {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(err_msg!(Backend, "Error starting transaction: store closed")),
            Err(_) => Err(err_msg!(
                Backend,
                "Error starting transaction: database is locked (another writer held it past busy_timeout)"
            )),
        }
    }

    /// Transactions waiting for admission (for tests).
    #[cfg(test)]
    pub(crate) fn waiting(&self) -> usize {
        self.waiting.load(std::sync::atomic::Ordering::Acquire)
    }
}

#[derive(Debug)]
pub struct DbSession<DB: ExtDatabase> {
    profile_key: DbSessionKey,
    state: DbSessionState<DB>,
    txn_depth: usize,
    /// A BEGIN/COMMIT/ROLLBACK was started and not acknowledged, so askar's
    /// and sqlx's view of the connection may disagree with the database.
    unsettled: bool,
    /// The backend's writer gate, when it has one (SQLite).
    write_gate: Option<WriteGate>,
    /// Held from admission until the transaction settles (or the session drops).
    write_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    /// The head this session was last admitted on.
    freshness_head: Option<Head>,
    /// When that admission happened; a transaction is not admitted again within its lease.
    admitted_at: Option<tokio::time::Instant>,
    /// The profile row is locked by the open transaction: it cannot be removed or replaced.
    profile_locked: bool,
    /// The latest activation read the profile row and found this session's profile.
    profile_checked: bool,
    pub(crate) freshness_dirty: bool,
    expected_freshness: Option<uuid::Uuid>,
    profile_name: String,
    profile_cache: Arc<KeyCache>,
    profile_fingerprint: Option<[u8; 32]>,
    profile_lock: ProfileLock,
    committer: Committer<DB>,
}

/// What a read was admitted on. A session outside a transaction checks it again after the
/// read when the read outlasted the lease (always, with a zero lease): the result of a read
/// is never returned on a confirmation older than one lease.
#[derive(Clone, Debug)]
pub(crate) struct ReadGuard {
    head: Option<Head>,
    expected: Option<uuid::Uuid>,
    admitted_at: Option<tokio::time::Instant>,
    in_transaction: bool,
}

impl ReadGuard {
    pub(crate) async fn check(&self) -> Result<(), Error> {
        // A transaction is admitted at activation, again whenever its admission is older
        // than the lease; its reads are not repeated and other writers may commit beside it.
        if self.in_transaction {
            return Ok(());
        }
        let lease = freshness::read_lease(self.head.as_ref());
        if !lease.is_zero() && self.admitted_at.is_some_and(|at| at.elapsed() < lease) {
            return Ok(());
        }
        // The captured admission head, never a newer local head: a newer head does not
        // authorize a result produced under an older one.
        freshness::check_for(self.head.as_ref(), self.expected).await
    }
}

impl<DB: ExtDatabase> DbSession<DB> {
    pub(crate) fn new(
        pool: Pool<DB>,
        cache: Arc<KeyCache>,
        profile: String,
        transaction: bool,
    ) -> Self
    where
        DB: Database,
    {
        Self {
            profile_name: profile,
            profile_cache: cache,
            profile_fingerprint: None,
            profile_key: DbSessionKey::Pending,
            state: DbSessionState::Pending { pool, transaction },
            txn_depth: 0,
            unsettled: false,
            write_gate: None,
            write_permit: None,
            freshness_head: None,
            admitted_at: None,
            profile_locked: false,
            profile_checked: false,
            freshness_dirty: false,
            expected_freshness: None,
            profile_lock: ProfileLock::default(),
            committer: Committer::default(),
        }
    }

    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    pub(crate) fn with_profile_lock(mut self, lock: ProfileLock) -> Self {
        self.profile_lock = lock;
        self
    }

    pub(crate) fn with_freshness_lineage(mut self, expected: Option<uuid::Uuid>) -> Self {
        self.expected_freshness = expected;
        self
    }
    /// Commit through the backend's shared committer, so concurrent commits share advances.
    pub(crate) fn with_committer(mut self, committer: Committer<DB>) -> Self {
        self.committer = committer;
        self
    }
    /// Admit this session's transaction through `gate` before it takes a connection.
    pub(crate) fn with_write_gate(mut self, gate: WriteGate) -> Self {
        self.write_gate = Some(gate);
        self
    }

    #[inline]
    fn connection_mut(&mut self) -> Option<&mut PoolConnection<DB>> {
        if let DbSessionState::Active { conn } = &mut self.state {
            Some(conn)
        } else {
            None
        }
    }

    #[inline]
    pub fn in_transaction(&self) -> bool {
        if self.txn_depth > 0 {
            return true;
        }
        if let DbSessionState::Pending {
            transaction: true, ..
        } = &self.state
        {
            return true;
        }
        false
    }

    pub(crate) fn read_guard(&self) -> ReadGuard {
        ReadGuard {
            head: self.freshness_head.clone(),
            expected: self.expected_freshness,
            admitted_at: self.admitted_at,
            in_transaction: self.txn_depth > 0,
        }
    }

    // The operation holds the session exclusively from admission through this check.
    pub(crate) async fn validate_read_head(&mut self) -> Result<(), Error> {
        self.read_guard().check().await
    }

    pub(crate) fn profile_and_key(&mut self) -> Option<(ProfileId, Arc<ProfileKey>)> {
        if let DbSessionKey::Active {
            profile_id,
            ref key,
        } = self.profile_key
        {
            Some((profile_id, key.clone()))
        } else {
            None
        }
    }

    /// Take a connection and, for a transactional session, begin its transaction.
    async fn connect(&mut self) -> Result<(), Error> {
        if self.unsettled {
            return Err(err_msg!(
                Backend,
                "Session unusable after an interrupted transaction command"
            ));
        }
        if let DbSessionState::Pending { pool, transaction } = &self.state {
            // Queue for the writer before taking a connection, never while holding one.
            let permit = match (&self.write_gate, *transaction) {
                (Some(gate), true) => Some(gate.admit().await?),
                _ => None,
            };
            debug!("Acquire pool connection");
            let conn = pool
                .acquire()
                .await
                .map_err(err_map!(Backend, "Error acquiring pool connection"))?;
            let mut conn = Unsettled::new(conn);
            if *transaction {
                debug!("Start transaction");
                DB::start_transaction(conn.conn(), false)
                    .await
                    .map_err(err_map!(Backend, "Error starting transaction"))?;
                self.txn_depth += 1;
            }
            self.write_permit = permit;
            self.state = DbSessionState::Active {
                conn: conn.settle(),
            };
        }
        if !matches!(self.state, DbSessionState::Active { .. }) {
            return Err(err_msg!(Backend, "Session closed"));
        }
        Ok(())
    }

    /// Admission of this session to the store as it is now. No head lock is ever taken here:
    /// the head is locked only by a commit that wrote, for the length of that commit.
    ///
    /// Outside a transaction every operation is admitted: one statement reads the head and
    /// this session's profile row, and the head is checked against the read lease or the
    /// witness. Inside a transaction the profile row is locked at the first admission, so the
    /// profile cannot change, and the admission is repeated only once it is older than the
    /// read lease (always, with a zero lease).
    async fn admit(&mut self, with_profile: bool) -> Result<(), Error> {
        self.connect().await?;
        self.profile_checked = false;
        let in_transaction = self.txn_depth > 0;
        let settled_profile =
            !with_profile || (self.profile_locked && self.profile_and_key().is_some());
        if in_transaction && settled_profile {
            if let Some(at) = self.admitted_at {
                if at.elapsed() < freshness::read_lease(self.freshness_head.as_ref()) {
                    return Ok(());
                }
            }
        }
        self.readmit(with_profile, in_transaction).await
    }

    async fn readmit(&mut self, with_profile: bool, lock: bool) -> Result<(), Error> {
        let name = self.profile_name.clone();
        // A head read without a lock can be one behind the witness for the length of another
        // writer's local COMMIT: admit on a fresh exact match, never on the head first read.
        // Only this admission is repeated, never a statement of the caller's.
        let mut retry = ReadRetry::new(false);
        let admitted = loop {
            let profile = match (&self.profile_key, with_profile) {
                (_, false) => ProfileRef::None,
                (DbSessionKey::Active { profile_id, .. }, true) => ProfileRef::Id(*profile_id),
                (DbSessionKey::Pending, true) => ProfileRef::Name(&name),
            };
            let mode = lock.then_some(self.profile_lock);
            let admitted =
                DB::admission(self.connection_mut().unwrap().as_mut(), profile, mode).await?;
            if retry.reread(admitted.head.as_ref()) {
                continue;
            }
            match freshness::check_for(admitted.head.as_ref(), self.expected_freshness).await {
                Ok(()) => break admitted,
                Err(error) if retry.again(&error).await => continue,
                Err(error) => return Err(error),
            }
        };
        if with_profile {
            self.adopt_profile(admitted.profile, admitted.head.is_some())
                .await?;
            self.profile_locked = lock;
        }
        self.freshness_head = admitted.head;
        self.admitted_at = Some(tokio::time::Instant::now());
        Ok(())
    }

    /// Bind this session to the profile row just read, or verify it is still the same one.
    ///
    /// The key comes from the cache only when the row read on this very admission has the
    /// profile id and the wrapped-key fingerprint the cached key was unwrapped from, so a
    /// profile that was removed and created again (even with a reused id) never resolves to
    /// the old key and never revives an old session.
    async fn adopt_profile(
        &mut self,
        row: Option<ProfileRow>,
        bound: bool,
    ) -> Result<(), Error> {
        use sha2::Digest;
        match (&self.profile_key, row) {
            (DbSessionKey::Pending, None) => Err(err_msg!(NotFound, "Profile not found")),
            (DbSessionKey::Active { .. }, None) => {
                Err(err_msg!(NotFound, "Session profile has been removed"))
            }
            (DbSessionKey::Pending, Some((profile_id, name, encoded_key))) => {
                let fingerprint: [u8; 32] = sha2::Sha256::digest(&encoded_key).into();
                let key = self
                    .profile_cache
                    .resolve_profile(&name, profile_id, fingerprint, encoded_key)
                    .await?;
                self.profile_key = DbSessionKey::Active { profile_id, key };
                self.profile_fingerprint = Some(fingerprint);
                self.profile_checked = true;
                Ok(())
            }
            (DbSessionKey::Active { .. }, Some((_, name, encoded_key))) => {
                // An unbound store keeps its earlier behaviour: rename and rekey are
                // supported there and do not invalidate a retained session.
                if bound {
                    if name != self.profile_name {
                        return Err(err_msg!(Backend, "Session profile identity changed"));
                    }
                    let fingerprint: [u8; 32] = sha2::Sha256::digest(&encoded_key).into();
                    if self.profile_fingerprint != Some(fingerprint) {
                        return Err(err_msg!(Backend, "Session profile key changed"));
                    }
                }
                self.profile_checked = true;
                Ok(())
            }
        }
    }

    // Metadata mutations use the SAME outer session admission/commit protocol,
    // without resolving/locking any profile (including the one being removed).
    pub(crate) async fn metadata_connection(&mut self) -> Result<&mut Connection<DB>, Error> {
        self.admit(false).await?;
        Ok(self.connection_mut().unwrap().as_mut())
    }

    pub(crate) async fn make_active(&mut self) -> Result<DbSessionActive<'_, DB>, Error> {
        self.admit(true).await?;
        let Some((profile_id, _)) = self.profile_and_key() else {
            return Err(err_msg!(Unexpected, "Session profile unresolved"));
        };
        Ok(DbSessionActive {
            inner: self,
            profile_id,
        })
    }

    #[inline]
    pub(crate) fn borrow_mut(&mut self) -> DbSessionRef<'_, DB> {
        DbSessionRef::Borrowed(self)
    }

    #[inline]
    pub(crate) fn owned_ref(self) -> DbSessionRef<'static, DB> {
        DbSessionRef::Owned(self)
    }

    /// The head this outermost commit must advance from: set when the store is bound and the
    /// transaction wrote. Read-only transactions and rollbacks never touch the head.
    fn advance_due(&self) -> Option<Head> {
        if self.freshness_dirty {
            self.freshness_head.clone()
        } else {
            None
        }
    }

    /// Hand the open transaction to the committer: it locks the head, advances the witness
    /// and commits. The committer owns the connection until the outcome is known, so a caller
    /// that stops waiting (a timeout, a dropped request) cannot leave the witness advanced
    /// beside a rolled-back transaction; this session stays unusable unless it is told the
    /// commit succeeded.
    async fn commit_advancing(&mut self, admitted: Head, keep: bool) -> Result<(), Error> {
        let DbSessionState::Active { conn } =
            std::mem::replace(&mut self.state, DbSessionState::Closed)
        else {
            return Err(err_msg!(Backend, "Session closed"));
        };
        self.unsettled = true;
        self.txn_depth = 0;
        let committer = self.committer.clone();
        let settled = committer
            .commit(conn, admitted, self.expected_freshness, keep)
            .await;
        // Settled either way: the next writer may take the database.
        self.write_permit = None;
        let conn = settled?;
        self.unsettled = false;
        self.freshness_dirty = false;
        self.freshness_head = None;
        self.admitted_at = None;
        self.profile_locked = false;
        if let Some(conn) = conn {
            self.state = DbSessionState::Active { conn };
        }
        Ok(())
    }

    pub(crate) async fn close(&mut self, commit: bool) -> Result<(), Error> {
        if self.unsettled {
            return Err(err_msg!(
                Backend,
                "Session unusable after an interrupted transaction command"
            ));
        }
        if self.txn_depth == 0 {
            self.state = DbSessionState::Closed;
            self.write_permit = None;
            return Ok(());
        }
        if !matches!(self.state, DbSessionState::Active { .. }) {
            warn!("Could not close out transaction: session not active");
            self.txn_depth = 0;
            self.state = DbSessionState::Closed;
            self.write_permit = None;
            return Ok(());
        }
        if commit {
            if let Some(admitted) = self.advance_due() {
                return self.commit_advancing(admitted, false).await;
            }
        }
        // The connection stays owned by the session until the database has
        // acknowledged the outcome; if this future is dropped first, `Drop`
        // recovers the connection instead of pooling it.
        self.unsettled = true;
        let conn = self.connection_mut().expect("active session");
        if commit {
            debug!("Commit transaction on close");
            DB::TransactionManager::commit(conn).await
        } else {
            debug!("Roll-back transaction on close");
            DB::TransactionManager::rollback(conn).await
        }
        .map_err(err_map!(Backend, "Error closing transaction"))?;
        self.unsettled = false;
        self.txn_depth = 0;
        self.freshness_dirty = false;
        self.profile_locked = false;
        if let DbSessionState::Active { mut conn } =
            std::mem::replace(&mut self.state, DbSessionState::Closed)
        {
            conn.return_to_pool().await;
        }
        // Settled: the next writer may take the database.
        self.write_permit = None;
        Ok(())
    }
}

impl<DB: ExtDatabase> Drop for DbSession<DB> {
    fn drop(&mut self) {
        let state = std::mem::replace(&mut self.state, DbSessionState::Closed);
        if let DbSessionState::Active { mut conn } = state {
            if self.unsettled {
                debug!("Dropped interrupted transaction command: recover connection");
                recover(conn);
            } else if self.txn_depth > 0 {
                debug!("Dropped transaction: roll-back");
                DB::TransactionManager::start_rollback(&mut conn);
            } else {
                debug!("Dropped pool connection")
            }
        }
        self.txn_depth = 0;
    }
}

#[derive(Debug)]
pub(crate) enum DbSessionKey {
    Active {
        profile_id: ProfileId,
        key: Arc<ProfileKey>,
    },
    Pending,
}

/// How a transaction locks its profile row.
///
/// Both keep the profile from being removed under the transaction (a DELETE needs the row
/// `FOR UPDATE`, which conflicts with either). They differ in what they do to each other:
///
/// - `NoKeyUpdate` conflicts with itself, so the transactions of one profile run strictly one
///   after another. Callers have been able to rely on that since upstream Askar: a
///   transaction that reads a record with a plain fetch and then replaces it cannot lose an
///   update to another transaction of the same profile.
/// - `KeyShare` does not conflict with itself: the profile's transactions overlap, under
///   READ COMMITTED. A read-modify-write is then safe only if the read is `for_update`
///   (which locks the item rows) or the caller serializes it otherwise. It also no longer
///   holds off a rekey, which rewrites the wrapped key and leaves the key itself unchanged;
///   a bound store refuses rekey and rename anyway.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProfileLock {
    /// `FOR NO KEY UPDATE`: the default.
    #[default]
    NoKeyUpdate,
    /// `FOR KEY SHARE`: `profile_lock=key_share` in the store URI.
    KeyShare,
}

impl ProfileLock {
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    pub(crate) fn parse(value: Option<String>) -> Result<Self, Error> {
        match value.as_deref() {
            None | Some("no_key_update") => Ok(Self::NoKeyUpdate),
            Some("key_share") => Ok(Self::KeyShare),
            Some(_) => Err(err_msg!(Input, "Invalid 'profile_lock' parameter")),
        }
    }
}

/// Which profile row an admission reads beside the head.
#[derive(Clone, Copy, Debug)]
pub enum ProfileRef<'a> {
    /// None: a metadata session.
    None,
    /// By name: a session's first admission.
    Name(&'a str),
    /// By id: every later admission.
    Id(ProfileId),
}

/// A profile row: id, name and wrapped profile key.
pub type ProfileRow = (ProfileId, String, Vec<u8>);

/// One admission read: the store's head and the profile row asked for.
#[derive(Debug)]
pub struct Admitted {
    /// The freshness head, absent on an unbound store.
    pub head: Option<Head>,
    /// The profile row, absent when none was asked for or none exists.
    pub profile: Option<ProfileRow>,
}

pub trait ExtDatabase: Database {
    /// The head and a profile row, read without any lock on the head. `lock` locks the
    /// profile row for the open transaction.
    fn admission<'a>(
        conn: &'a mut Connection<Self>,
        profile: ProfileRef<'a>,
        lock: Option<ProfileLock>,
    ) -> BoxFuture<'a, Result<Admitted, Error>>;

    /// The head; `lock` takes it for the rest of the open transaction and is used only by a
    /// commit that is about to advance it, and by binding.
    fn freshness_head(
        conn: &mut Connection<Self>,
        lock: bool,
    ) -> BoxFuture<'_, Result<Option<super::freshness::Head>, Error>>;
    fn freshness_write<'a>(
        conn: &'a mut Connection<Self>,
        head: &'a super::freshness::Head,
    ) -> BoxFuture<'a, Result<(), Error>>;
    /// Write the next head in a transaction that holds the head lock from
    /// `freshness_head(conn, true)`.
    fn freshness_advance<'a>(
        conn: &'a mut Connection<Self>,
        head: &'a super::freshness::Head,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Self::freshness_write(conn, head)
    }

    fn start_transaction(
        conn: &mut Connection<Self>,
        _nested: bool,
    ) -> BoxFuture<'_, Result<(), SqlxError>> {
        <Self as Database>::TransactionManager::begin(conn, None)
    }

    /// Restore a connection whose last transaction command was interrupted.
    /// `false` means it must not be reused.
    fn reset_connection(conn: &mut Connection<Self>) -> BoxFuture<'_, bool> {
        Box::pin(reset_depth::<Self>(conn))
    }
}

pub enum DbSessionRef<'q, DB: ExtDatabase> {
    Owned(DbSession<DB>),
    Borrowed(&'q mut DbSession<DB>),
}

impl<DB: ExtDatabase> DbSessionRef<'_, DB> {
    pub fn is_owned(&self) -> bool {
        matches!(self, Self::Owned(_))
    }
}

impl<DB: ExtDatabase> Deref for DbSessionRef<'_, DB> {
    type Target = DbSession<DB>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(e) => e,
            Self::Borrowed(e) => e,
        }
    }
}

impl<DB: ExtDatabase> DerefMut for DbSessionRef<'_, DB> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Owned(e) => e,
            Self::Borrowed(e) => e,
        }
    }
}

pub(crate) struct DbSessionActive<'a, DB: ExtDatabase> {
    inner: &'a mut DbSession<DB>,
    pub(crate) profile_id: ProfileId,
}

impl<'q, DB: ExtDatabase> DbSessionActive<'q, DB> {
    pub(crate) fn read_guard(&self) -> ReadGuard {
        self.inner.read_guard()
    }
    /// See [`ReadGuard`].
    pub(crate) async fn check_read(&self) -> Result<(), Error> {
        self.inner.read_guard().check().await
    }
    /// This activation read the profile row and found the session's profile.
    pub(crate) fn profile_checked(&self) -> bool {
        self.inner.profile_checked
    }
    #[inline]
    pub fn connection_mut(&mut self) -> &mut Connection<DB> {
        self.inner
            .connection_mut()
            .expect("Tried to fetch connection from closed session")
            .as_mut()
    }

    #[allow(unused)]
    pub fn in_transaction(&self) -> bool {
        self.inner.in_transaction()
    }

    #[allow(unused)]
    pub async fn begin<'t>(&'t mut self) -> Result<DbSessionTxn<'t, DB>, Error>
    where
        'q: 't,
    {
        debug!("Start nested transaction");
        self.inner.unsettled = true;
        DB::start_transaction(self.connection_mut(), true)
            .await
            .map_err(err_map!(Backend, "Error starting nested transaction"))?;
        self.inner.unsettled = false;
        self.inner.txn_depth += 1;
        Ok(DbSessionTxn {
            inner: &mut *self.inner,
            profile_id: self.profile_id,
            rollback: true,
        })
    }

    pub async fn as_transaction<'t>(&'t mut self) -> Result<DbSessionTxn<'t, DB>, Error>
    where
        'q: 't,
    {
        if self.inner.txn_depth == 0 {
            debug!("Start transaction");
            self.inner.unsettled = true;
            DB::start_transaction(self.connection_mut(), false)
                .await
                .map_err(err_map!(Backend, "Error starting transaction"))?;
            self.inner.unsettled = false;
            self.inner.txn_depth += 1;
            // Admitted again inside the transaction. On a bound store the profile row is
            // now locked for its length; an unbound store never locked it for an implicit
            // write and still does not (the write may be serving a transaction that holds
            // it). The head is not locked: the commit locks it.
            let bound = self.inner.freshness_head.is_some();
            if let Err(error) = self.inner.readmit(true, bound).await {
                // The transaction is open and nothing owns it: the session must not be used
                // again (a later write would join it and never commit). Drop rolls it back.
                self.inner.unsettled = true;
                return Err(error);
            }
            Ok(DbSessionTxn {
                inner: &mut *self.inner,
                profile_id: self.profile_id,
                rollback: true,
            })
        } else {
            Ok(DbSessionTxn {
                inner: &mut *self.inner,
                profile_id: self.profile_id,
                rollback: false,
            })
        }
    }
}

pub(crate) struct DbSessionTxn<'a, DB: ExtDatabase> {
    inner: &'a mut DbSession<DB>,
    pub(crate) profile_id: ProfileId,
    rollback: bool,
}

impl<DB: ExtDatabase> DbSessionTxn<'_, DB> {
    pub(crate) fn mark_dirty(&mut self) {
        self.inner.freshness_dirty = true;
    }
    pub fn connection_mut(&mut self) -> &mut Connection<DB> {
        self.inner.connection_mut().unwrap().as_mut()
    }

    pub async fn commit(mut self) -> Result<(), Error> {
        if self.rollback {
            if self.inner.txn_depth == 1 {
                if let Some(admitted) = self.inner.advance_due() {
                    self.rollback = false;
                    return self.inner.commit_advancing(admitted, true).await;
                }
            }
            self.rollback = false;
            self.inner.txn_depth -= 1;
            self.inner.unsettled = true;
            let conn = self.connection_mut();
            debug!("Commit transaction");
            DB::TransactionManager::commit(conn)
                .await
                .map_err(err_map!(Backend, "Error committing transaction"))?;
            self.inner.unsettled = false;
            if self.inner.txn_depth == 0 {
                self.inner.freshness_head = None;
                self.inner.admitted_at = None;
                self.inner.profile_locked = false;
                self.inner.freshness_dirty = false;
            }
        }
        Ok(())
    }
}

impl<DB: ExtDatabase> Drop for DbSessionTxn<'_, DB> {
    fn drop(&mut self) {
        if self.rollback {
            self.inner.txn_depth -= 1;
            if self.inner.txn_depth == 0 {
                self.inner.admitted_at = None;
                self.inner.profile_locked = false;
                self.inner.freshness_dirty = false;
            }
            debug!("Roll-back dropped nested transaction");
            DB::TransactionManager::start_rollback(self.connection_mut());
        }
    }
}

pub struct EncScanEntry {
    pub kind: EntryKind,
    pub category: Vec<u8>,
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub tags: Vec<u8>,
}

pub struct QueryParams<'q, DB: Database> {
    args: DB::Arguments<'q>,
    count: usize,
}

impl<'q, DB: Database> QueryParams<'q, DB> {
    pub fn new() -> Self {
        Self {
            args: Default::default(),
            count: 0,
        }
    }

    pub fn extend<I, T>(&mut self, vals: I)
    where
        I: IntoIterator<Item = T>,
        T: 'q + Send + sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    {
        for item in vals {
            self.args.add(item).expect("too many arguments");
            self.count += 1;
        }
    }

    pub fn push<T>(&mut self, val: T)
    where
        T: 'q + Send + sqlx::Encode<'q, DB> + sqlx::Type<DB>,
    {
        self.args.add(val).expect("too many arguments");
        self.count += 1;
    }

    pub fn len(&self) -> usize {
        self.count
    }
}

impl<'q, DB> IntoArguments<'q, DB> for QueryParams<'q, DB>
where
    DB: Database,
    DB::Arguments<'q>: IntoArguments<'q, DB>,
{
    fn into_arguments(self) -> DB::Arguments<'q> {
        self.args.into_arguments()
    }
}

pub trait QueryPrepare {
    type DB: Database;

    fn placeholder(index: i64) -> String {
        format!("?{}", index)
    }

    fn limit_query<'q>(
        mut query: String,
        args: &mut QueryParams<'q, Self::DB>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> String
    where
        i64: for<'e> Encode<'e, Self::DB> + Type<Self::DB>,
    {
        if offset.is_some() || limit.is_some() {
            let last_idx = (args.len() + 1) as i64;
            args.push(offset.unwrap_or(0));
            args.push(limit.unwrap_or(-1));
            let limit = replace_arg_placeholders::<Self>(" LIMIT $$, $$", last_idx);
            query.push_str(&limit);
        }
        query
    }

    fn order_by_query(mut query: String, order_by: OrderBy, descending: bool) -> String {
        query.push_str(" ORDER BY ");
        match order_by {
            OrderBy::Id => query.push_str("id"),
        }
        if descending {
            query.push_str(" DESC");
        }
        query
    }
}

pub fn replace_arg_placeholders<Q: QueryPrepare + ?Sized>(
    filter: &str,
    start_index: i64,
) -> String {
    let mut index = start_index;
    let mut buffer: String = String::with_capacity(filter.len());
    let mut remain = filter;
    while let Some(start_offs) = remain.find('$') {
        let mut iter = remain[(start_offs + 1)..].chars();
        if let Some((end_offs, sub_index)) = iter.next().and_then(|c| match c {
            '$' => Some((start_offs + 2, index)),
            '0'..='9' => {
                let mut end_offs = start_offs + 2;
                for c in iter {
                    if c.is_ascii_digit() {
                        end_offs += 1;
                    } else {
                        break;
                    }
                }
                Some((
                    end_offs,
                    remain[(start_offs + 1)..end_offs].parse::<i64>().unwrap() + start_index - 1,
                ))
            }
            _ => None,
        }) {
            buffer.push_str(&remain[..start_offs]);
            buffer.push_str(&Q::placeholder(sub_index));
            remain = &remain[end_offs..];
            index += 1;
        } else {
            buffer.push_str(&remain[..=start_offs]);
            remain = &remain[(start_offs + 1)..];
        }
    }
    buffer.push_str(remain);
    buffer
}

pub(crate) fn decode_tags(tags: Vec<u8>) -> Result<Vec<EncEntryTag>, ()> {
    let mut idx = 0;
    let mut plaintext;
    let mut name_start;
    let mut name_end;
    let mut enc_tags = vec![];
    let end = tags.len();
    loop {
        if idx >= end {
            break;
        }
        plaintext = tags[idx] == b'1';
        // assert ':' at idx + 1
        idx += 2;
        name_start = idx;
        name_end = 0;
        loop {
            if idx >= end || tags[idx] == b',' {
                if name_end == 0 {
                    return Err(());
                }
                let name = hex::decode(&tags[(name_start)..(name_end)]).map_err(|_| ())?;
                let value = hex::decode(&tags[(name_end + 1)..(idx)]).map_err(|_| ())?;
                enc_tags.push(EncEntryTag {
                    name,
                    value,
                    plaintext,
                });
                break;
            }
            if tags[idx] == b':' {
                if name_end != 0 {
                    return Err(());
                }
                name_end = idx;
            }
            idx += 1;
        }
        idx += 1;
    }
    Ok(enc_tags)
}

pub fn decrypt_scan_batch(
    category: Option<String>,
    enc_rows: Vec<EncScanEntry>,
    key: &ProfileKey,
) -> Result<Vec<Entry>, Error> {
    let mut batch = Vec::with_capacity(enc_rows.len());
    for enc_entry in enc_rows {
        batch.push(decrypt_scan_entry(category.as_deref(), enc_entry, key)?);
    }
    Ok(batch)
}

pub fn decrypt_scan_entry(
    category: Option<&str>,
    enc_entry: EncScanEntry,
    key: &ProfileKey,
) -> Result<Entry, Error> {
    let category = match category {
        Some(c) => c.to_owned(),
        None => key.decrypt_entry_category(enc_entry.category)?,
    };
    let name = key.decrypt_entry_name(enc_entry.name)?;
    let value = key.decrypt_entry_value(category.as_bytes(), name.as_bytes(), enc_entry.value)?;
    let tags = key.decrypt_entry_tags(
        decode_tags(enc_entry.tags).map_err(|_| err_msg!(Unexpected, "Error decoding tags"))?,
    )?;
    Ok(Entry::new(enc_entry.kind, category, name, value, tags))
}

pub fn expiry_timestamp(expire_ms: i64) -> Result<Expiry, Error> {
    chrono::Utc::now()
        .checked_add_signed(chrono::Duration::milliseconds(expire_ms))
        .ok_or_else(|| err_msg!(Unexpected, "Invalid expiry timestamp"))
}

#[allow(clippy::type_complexity)]
pub fn encode_tag_filter<Q: QueryPrepare>(
    tag_filter: Option<TagFilter>,
    key: &ProfileKey,
    offset: usize,
) -> Result<Option<(String, Vec<Vec<u8>>)>, Error> {
    if let Some(tag_filter) = tag_filter {
        let tag_query = tag_query(tag_filter.query)?;
        let mut enc = TagSqlEncoder::new(
            |name| key.encrypt_tag_name(ProfileKey::prepare_input(name.as_bytes())),
            |value| key.encrypt_tag_value(ProfileKey::prepare_input(value.as_bytes())),
        );
        if let Some(filter) = enc.encode_query(&tag_query)? {
            let filter = replace_arg_placeholders::<Q>(&filter, (offset as i64) + 1);
            Ok(Some((filter, enc.arguments)))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

// allocate a String while ensuring there is sufficient capacity to reuse during encryption
fn _prepare_string(value: &str) -> String {
    let buf = ProfileKey::prepare_input(value.as_bytes()).into_vec();
    unsafe { String::from_utf8_unchecked(buf) }
}

// convert a slice of tags into a Vec, while ensuring there is
// adequate space in the allocations to reuse them during encryption
pub fn prepare_tags(tags: &[EntryTag]) -> Result<Vec<EntryTag>, Error> {
    let mut result = Vec::with_capacity(tags.len());
    for tag in tags {
        result.push(match tag {
            EntryTag::Plaintext(name, value) => {
                EntryTag::Plaintext(_prepare_string(name), value.clone())
            }
            EntryTag::Encrypted(name, value) => {
                EntryTag::Encrypted(_prepare_string(name), _prepare_string(value))
            }
        });
    }
    Ok(result)
}

pub fn extend_query<'q, Q: QueryPrepare>(
    query: &str,
    args: &mut QueryParams<'q, Q::DB>,
    tag_filter: Option<(String, Vec<Vec<u8>>)>,
    offset: Option<i64>,
    limit: Option<i64>,
    order_by: Option<OrderBy>,
    descending: bool,
) -> Result<String, Error>
where
    i64: for<'e> Encode<'e, Q::DB> + Type<Q::DB>,
    Vec<u8>: for<'e> Encode<'e, Q::DB> + Type<Q::DB>,
{
    let mut query = query.to_string();
    if let Some((filter_clause, filter_args)) = tag_filter {
        args.extend(filter_args);
        query.push_str(" AND "); // assumes WHERE already occurs
        query.push_str(&filter_clause);
    };
    // Only add ordering, and limit/offset, if the query starts with SELECT
    if query.trim_start().to_uppercase().starts_with("SELECT") {
        if let Some(order_by_value) = order_by {
            query = Q::order_by_query(query, order_by_value, descending);
        };

        if offset.is_some() || limit.is_some() {
            query = Q::limit_query(query, args, offset, limit);
        };
    }
    Ok(query)
}

pub fn init_keys(
    method: StoreKeyMethod,
    pass_key: PassKey<'_>,
) -> Result<(ProfileKey, Vec<u8>, StoreKey, String), Error> {
    if method == StoreKeyMethod::RawKey && pass_key.is_empty() {
        // disallow random key for a new database
        return Err(err_msg!(
            Input,
            "Cannot create a store with a blank raw key"
        ));
    }
    let (store_key, store_key_ref) = method.resolve(pass_key)?;
    let profile_key = ProfileKey::new()?;
    let enc_profile_key = encode_profile_key(&profile_key, &store_key)?;
    Ok((
        profile_key,
        enc_profile_key,
        store_key,
        store_key_ref.into_uri(),
    ))
}

pub fn encode_profile_key(
    profile_key: &ProfileKey,
    store_key: &StoreKey,
) -> Result<Vec<u8>, Error> {
    store_key.wrap_data(profile_key.to_bytes()?)
}

#[inline]
pub fn random_profile_name() -> String {
    uuid::Uuid::new_v4().to_string()
}
