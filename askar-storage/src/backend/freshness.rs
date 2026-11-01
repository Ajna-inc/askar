//! Independent, durable freshness heads. A witness must have a separate restore domain.
//! Missing or ambiguous witness outcomes fail closed; there is no rewind operation.
use crate::error::Error;
use serde::{Deserialize, Serialize};

pub(crate) const HEAD_KEY: &str = "askar_freshness_head_v1";

/// A lineage and exact commit identity; counters alone cannot distinguish divergent copies.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Head {
    /// Stable random identifier of the trusted store lineage.
    pub lineage: uuid::Uuid,
    /// Checked, non-wrapping durable commit sequence.
    pub sequence: u64,
    /// Random commit identity, distinguishing divergent branches.
    pub token: uuid::Uuid,
}
impl Head {
    /// Generate the head for an explicit trusted-current binding.
    pub fn initial() -> Self {
        Self {
            lineage: uuid::Uuid::new_v4(),
            sequence: 0,
            token: uuid::Uuid::new_v4(),
        }
    }
    /// Generate a fresh next head, refusing sequence overflow.
    pub fn next(&self) -> Result<Self, Error> {
        Ok(Self {
            lineage: self.lineage,
            sequence: self
                .sequence
                .checked_add(1)
                .ok_or_else(|| err_msg!(Backend, "Freshness sequence exhausted"))?,
            token: uuid::Uuid::new_v4(),
        })
    }
    pub(crate) fn decode(value: &str) -> Result<Self, Error> {
        let head: Self = serde_json::from_str(value)
            .map_err(|_| err_msg!(Backend, "Invalid freshness metadata"))?;
        if head.lineage.is_nil() || head.token.is_nil() {
            return Err(err_msg!(Backend, "Invalid freshness metadata"));
        }
        Ok(head)
    }
    pub(crate) fn encode(&self) -> Result<String, Error> {
        serde_json::to_string(self).map_err(|_| err_msg!(Backend, "Invalid freshness metadata"))
    }
}

#[cfg(feature = "postgres")]
fn witness_options(uri: &str) -> Result<sqlx::postgres::PgConnectOptions, Error> {
    use std::str::FromStr;
    let url = url::Url::parse(uri).map_err(|_| err_msg!(Input, "Invalid freshness witness URI"))?;
    let modes = url
        .query_pairs()
        .filter(|(k, _)| k == "sslmode" || k == "ssl-mode")
        .count();
    if !matches!(url.scheme(), "postgres" | "postgresql") || modes > 1 {
        return Err(err_msg!(
            Input,
            "Invalid freshness witness transport configuration"
        ));
    }
    let options = sqlx::postgres::PgConnectOptions::from_str(uri)
        .map_err(|_| err_msg!(Input, "Invalid freshness witness URI"))?;
    let effective_host = options.get_host();
    let loopback = effective_host == "localhost"
        || effective_host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if options.get_socket().is_some()
        || (!loopback
            && !matches!(
                options.get_ssl_mode(),
                sqlx::postgres::PgSslMode::VerifyFull
            ))
    {
        return Err(err_msg!(
            Input,
            "Freshness witness requires verified TLS outside loopback"
        ));
    }
    Ok(options.options([
        ("statement_timeout", "5000"),
        ("lock_timeout", "5000"),
        ("synchronous_commit", "on"),
    ]))
}

#[cfg(feature = "postgres")]
async fn witness_query<T>(
    future: impl std::future::Future<Output = Result<T, sqlx::Error>>,
) -> Result<T, Error> {
    tokio::time::timeout(std::time::Duration::from_secs(5), future)
        .await
        .map_err(|_| err_msg!(Backend, "Freshness witness outcome unresolved"))?
        .map_err(|_| {
            err_msg!(
                Backend,
                "Freshness witness unavailable or outcome unresolved"
            )
        })
}

/// How many times a compare-and-advance whose outcome is unknown is asked again.
#[cfg(feature = "postgres")]
const ADVANCE_ATTEMPTS: u32 = 4;

/// Independently durable PostgreSQL register. Debug never includes credentials.
#[cfg(feature = "postgres")]
#[derive(Clone)]
pub struct PostgresWitness {
    pool: sqlx::PgPool,
    /// Kept for compare-and-advance, so that read checks can never starve a commit.
    advances: sqlx::PgPool,
}
#[cfg(feature = "postgres")]
impl std::fmt::Debug for PostgresWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PostgresWitness { credentials: [redacted] }")
    }
}
#[cfg(feature = "postgres")]
impl PostgresWitness {
    /// Connect only. Normal serving never creates the schema or a missing lineage.
    ///
    /// `ASKAR_FRESHNESS_WITNESS_POOL` (default 8, at least 2) sizes two pools: one serves read
    /// checks, the other compare-and-advance, so read checks can never starve a commit. With
    /// a read lease a process issues at most one read check per lineage at a time, and it
    /// always has at most one advance per lineage in flight, so the default covers eight
    /// lineages on one witness; a single store opens one or two connections of each pool.
    /// The advance pool connects on first use and gives idle connections back.
    pub async fn connect(uri: &str) -> Result<Self, Error> {
        let options = witness_options(uri)?;
        let size = std::env::var("ASKAR_FRESHNESS_WITNESS_POOL")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(8)
            .max(2);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(size)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_with(options.clone())
            .await
            .map_err(|_| err_msg!(Backend, "Freshness witness unavailable"))?;
        let advances = sqlx::postgres::PgPoolOptions::new()
            .max_connections(size)
            .min_connections(0)
            .idle_timeout(std::time::Duration::from_secs(60))
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect_lazy_with(options);
        Ok(Self { pool, advances })
    }
    /// Explicit operator bootstrap; do not invoke on a normal serving path.
    pub async fn provision(&self) -> Result<(), Error> {
        witness_query(sqlx::query("CREATE TABLE IF NOT EXISTS askar_freshness_witness_v1 (lineage TEXT PRIMARY KEY, sequence TEXT NOT NULL, token TEXT NOT NULL)")
            .execute(&self.pool)).await?;
        Ok(())
    }
    /// Register a trusted-current, quiescent store exactly once. Never upsert.
    pub async fn register(&self, head: &Head) -> Result<(), Error> {
        witness_query(sqlx::query("INSERT INTO askar_freshness_witness_v1 (lineage, sequence, token) VALUES ($1,$2,$3)")
            .bind(head.lineage.to_string()).bind(head.sequence.to_string()).bind(head.token.to_string())
            .execute(&self.pool)).await?;
        Ok(())
    }
    async fn row(&self, pool: &sqlx::PgPool, lineage: uuid::Uuid) -> Result<Option<(String, String)>, Error> {
        witness_query(
            sqlx::query_as(
                "SELECT sequence, token FROM askar_freshness_witness_v1 WHERE lineage=$1",
            )
            .bind(lineage.to_string())
            .fetch_optional(pool),
        )
        .await
    }
    /// Refuse when the independent register does not exactly match.
    pub async fn check(&self, head: &Head) -> Result<(), Error> {
        WITNESS_CHECKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let found = self.row(&self.pool, head.lineage).await?;
        if found != Some((head.sequence.to_string(), head.token.to_string())) {
            let mut error = err_msg!(Backend, "Store freshness refused: stale or missing witness");
            // A valid forward head can be a live writer race, or a stale clone. It
            // authorizes NO result: callers may only repeat the entire read and
            // must obtain an exact match on its newly admitted local head.
            error.read_head_moved = found.as_ref().is_some_and(|(sequence, token)| {
                match (sequence.parse::<u64>(), uuid::Uuid::parse_str(token)) {
                    (Ok(sequence_value), Ok(token_value)) => {
                        sequence_value > head.sequence
                            && sequence_value.to_string() == *sequence
                            && !token_value.is_nil()
                            && token_value.to_string() == *token
                    }
                    _ => false,
                }
            });
            return Err(error);
        }
        Ok(())
    }
    fn valid_advance(previous: &Head, next: &Head) -> Result<(), Error> {
        if next.lineage != previous.lineage
            || next.sequence
                != previous
                    .sequence
                    .checked_add(1)
                    .ok_or_else(|| err_msg!(Backend, "Freshness sequence exhausted"))?
            || next.token == previous.token
            || next.token.is_nil()
        {
            return Err(err_msg!(Backend, "Invalid freshness advance"));
        }
        Ok(())
    }
    /// One compare-and-advance. `Ok(false)`: the register did not hold `previous`.
    async fn compare_and_advance(&self, previous: &Head, next: &Head) -> Result<bool, Error> {
        WITNESS_ADVANCES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        #[cfg(test)]
        let lose_answer = read_race_tests::lose_advance_answer(previous);
        let changed = witness_query(sqlx::query("UPDATE askar_freshness_witness_v1 SET sequence=$4, token=$5 WHERE lineage=$1 AND sequence=$2 AND token=$3")
            .bind(previous.lineage.to_string()).bind(previous.sequence.to_string()).bind(previous.token.to_string())
            .bind(next.sequence.to_string()).bind(next.token.to_string()).execute(&self.advances)).await?;
        #[cfg(test)]
        if lose_answer {
            return Err(err_msg!(Backend, "Freshness witness outcome unresolved"));
        }
        Ok(changed.rows_affected() == 1)
    }
    /// Atomic durable CAS, attempted once. An error is ambiguous and must never trigger
    /// rewind; a committer uses [`Self::advance_resolved`].
    pub async fn advance(&self, previous: &Head, next: &Head) -> Result<(), Error> {
        Self::valid_advance(previous, next)?;
        if !self.compare_and_advance(previous, next).await? {
            return Err(err_msg!(Backend, "Freshness advance refused: stale store"));
        }
        Ok(())
    }
    /// The compare-and-advance of a commit, carried to a known outcome when there is one.
    ///
    /// An attempt that ends without the register's answer (the deadline fired, the connection
    /// was lost) may or may not have been applied. It is never assumed failed: the identical
    /// statement is issued again. `next.token` is random and known only to this process, and
    /// the register's row serializes the statements, so after any attempt has answered the
    /// register holds `next` if and only if one of them applied:
    ///
    /// - an attempt changes the row: applied;
    /// - an attempt changes nothing and the register holds exactly `next`: an earlier attempt
    ///   applied;
    /// - an attempt changes nothing and the register holds anything else: refused, the store
    ///   is stale or forked. Nothing was advanced on this commit's behalf.
    ///
    /// Only when no attempt is answered at all is the outcome unknown; the caller must then
    /// not commit, and must make this same advance again before any other from `previous`.
    pub(crate) async fn advance_resolved(
        &self,
        previous: &Head,
        next: &Head,
    ) -> Result<Advance, Error> {
        Self::valid_advance(previous, next)?;
        for attempt in 0..ADVANCE_ATTEMPTS {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(50 << attempt)).await;
            }
            match self.compare_and_advance(previous, next).await {
                Ok(true) => return Ok(Advance::Applied),
                Ok(false) => match self.row(&self.advances, previous.lineage).await {
                    Ok(found)
                        if found == Some((next.sequence.to_string(), next.token.to_string())) =>
                    {
                        return Ok(Advance::Applied)
                    }
                    Ok(_) => return Ok(Advance::Refused),
                    Err(_) => continue,
                },
                Err(_) => continue,
            }
        }
        Ok(Advance::Unknown)
    }
}

/// What the witness did with a commit's compare-and-advance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Advance {
    /// The witness holds the next head.
    Applied,
    /// The witness did not hold the previous head: this store is stale or forked.
    Refused,
    /// No attempt was answered: the witness may hold either head.
    Unknown,
}

static WITNESS_CHECKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static WITNESS_ADVANCES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LEASE_ADMISSIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static COMMIT_BATCHES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static COMMITS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Process-wide counts of what the fence asked of the witness and of the store's head.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FenceStats {
    /// Read checks sent to the witness.
    pub witness_checks: u64,
    /// Compare-and-advance statements sent to the witness, repeats included.
    pub witness_advances: u64,
    /// Admissions and read checks satisfied by the read lease, with no witness query.
    pub lease_admissions: u64,
    /// Head advances: one witness compare-and-advance and one head write each.
    pub commit_batches: u64,
    /// Transactions committed under those advances.
    pub commits: u64,
}

/// Read the fence counters.
pub fn fence_stats() -> FenceStats {
    use std::sync::atomic::Ordering::Relaxed;
    FenceStats {
        witness_checks: WITNESS_CHECKS.load(Relaxed),
        witness_advances: WITNESS_ADVANCES.load(Relaxed),
        lease_admissions: LEASE_ADMISSIONS.load(Relaxed),
        commit_batches: COMMIT_BATCHES.load(Relaxed),
        commits: COMMITS.load(Relaxed),
    }
}
pub(crate) fn count_batch(commits: usize) {
    use std::sync::atomic::Ordering::Relaxed;
    COMMIT_BATCHES.fetch_add(1, Relaxed);
    COMMITS.fetch_add(commits as u64, Relaxed);
}

// Credentials are deployment configuration, never database fields. A bound store without
// configuration refuses, including already-open sessions. Expected lineage also refuses
// pre-binding backups, whose local head would otherwise be absent.
pub(crate) fn expected_lineage() -> Result<Option<uuid::Uuid>, Error> {
    match std::env::var("ASKAR_FRESHNESS_LINEAGE") {
        Ok(v) => uuid::Uuid::parse_str(&v)
            .map(Some)
            .map_err(|_| err_msg!(Input, "Invalid expected freshness lineage")),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(err_msg!(Input, "Invalid expected freshness lineage")),
    }
}
pub(crate) fn parse_lineage(value: Option<String>) -> Result<Option<uuid::Uuid>, Error> {
    value
        .map(|v| {
            uuid::Uuid::parse_str(&v)
                .map_err(|_| err_msg!(Input, "Invalid store freshness lineage"))
        })
        .transpose()
}
/// How long a witness confirmation of one exact head admits reads without asking again.
///
/// `ASKAR_FRESHNESS_READ_LEASE_MS` (default 1000) for the process, `freshness_read_lease_ms`
/// in a store's URI for that store's lineage. Zero asks the witness on every admission and
/// after every read, as before the lease existed.
pub fn default_read_lease() -> std::time::Duration {
    std::time::Duration::from_millis(
        std::env::var("ASKAR_FRESHNESS_READ_LEASE_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1000),
    )
}
pub(crate) fn parse_read_lease(
    value: Option<String>,
) -> Result<Option<std::time::Duration>, Error> {
    value
        .map(|v| {
            v.parse::<u64>()
                .map(std::time::Duration::from_millis)
                .map_err(|_| err_msg!(Input, "Invalid store freshness read lease"))
        })
        .transpose()
}
/// Set, or with `None` clear, the read lease of one lineage in this process.
pub fn set_read_lease(lineage: uuid::Uuid, lease: Option<std::time::Duration>) {
    *Lineage::of(lineage).lease.lock().unwrap() = lease;
}
/// The read lease that applies to a store at `head`.
pub(crate) fn read_lease(head: Option<&Head>) -> std::time::Duration {
    head.map(|head| Lineage::of(head.lineage).lease())
        .unwrap_or_else(default_read_lease)
}

#[derive(Default)]
struct Verified {
    /// The newest head the witness is known to hold, and when that was learnt.
    current: Option<(Head, tokio::time::Instant)>,
    /// The head this process advanced the witness from, until the local COMMIT that makes
    /// its successor visible is acknowledged. The witness held it at the instant of the
    /// compare-and-advance, and this very database is the one moving past it.
    in_flight: Option<(Head, tokio::time::Instant)>,
    /// Heads this process committed past. A read that still sees one raced a local COMMIT.
    superseded: std::collections::VecDeque<Head>,
    /// An advance `(previous, next)` of this process that the witness never answered. The
    /// witness may hold either head; no transaction committed under it.
    unanswered: Option<(Head, Head)>,
}

/// What this process knows about one lineage. Memory only: a new process knows nothing and
/// asks the witness.
pub(crate) struct Lineage {
    lease: std::sync::Mutex<Option<std::time::Duration>>,
    verified: std::sync::Mutex<Verified>,
    /// One witness read check at a time: concurrent admissions on a cold lease share it.
    flight: tokio::sync::Mutex<()>,
}
impl Lineage {
    pub(crate) fn of(lineage: uuid::Uuid) -> std::sync::Arc<Self> {
        static LINEAGES: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<uuid::Uuid, std::sync::Arc<Lineage>>>,
        > = std::sync::OnceLock::new();
        LINEAGES
            .get_or_init(Default::default)
            .lock()
            .unwrap()
            .entry(lineage)
            .or_insert_with(|| {
                std::sync::Arc::new(Lineage {
                    lease: Default::default(),
                    verified: Default::default(),
                    flight: Default::default(),
                })
            })
            .clone()
    }
    fn lease(&self) -> std::time::Duration {
        self.lease.lock().unwrap().unwrap_or_else(default_read_lease)
    }
    /// The witness confirmed exactly `head` less than `lease` ago.
    fn leased(&self, head: &Head, lease: std::time::Duration) -> bool {
        let verified = self.verified.lock().unwrap();
        let now = tokio::time::Instant::now();
        let fresh = |known: &Option<(Head, tokio::time::Instant)>| {
            known
                .as_ref()
                .is_some_and(|(known, at)| known == head && now.saturating_duration_since(*at) < lease)
        };
        fresh(&verified.current) || fresh(&verified.in_flight)
    }
    fn confirmed(&self, head: &Head) {
        let mut verified = self.verified.lock().unwrap();
        // A confirmation that raced this process's own advance is already history.
        if verified
            .current
            .as_ref()
            .is_some_and(|(known, _)| known.sequence > head.sequence)
        {
            return;
        }
        verified.current = Some((head.clone(), tokio::time::Instant::now()));
    }
    fn superseded(&self, head: &Head) -> bool {
        self.verified.lock().unwrap().superseded.contains(head)
    }
    /// The head an advance from `previous` must move to, when an earlier advance from it was
    /// never answered: that same head, so that the statement sent now is the statement sent
    /// then and whichever of them the witness applies, it holds this head afterwards.
    pub(crate) fn unanswered_from(&self, previous: &Head) -> Option<Head> {
        match &self.verified.lock().unwrap().unanswered {
            Some((from, to)) if from == previous => Some(to.clone()),
            _ => None,
        }
    }
    pub(crate) fn unanswered(&self, advance: Option<(&Head, &Head)>) {
        self.verified.lock().unwrap().unanswered =
            advance.map(|(previous, next)| (previous.clone(), next.clone()));
    }
    /// The witness now holds `next`; it held `previous` until this instant.
    /// `asked` is when the advance was first sent: the lease of `previous` runs from the
    /// last instant the witness is known to have held it, not from when the answer arrived.
    pub(crate) fn advanced(&self, previous: &Head, next: &Head, asked: tokio::time::Instant) {
        let mut verified = self.verified.lock().unwrap();
        let now = tokio::time::Instant::now();
        verified.in_flight = Some((previous.clone(), asked));
        verified.current = Some((next.clone(), now));
        verified.unanswered = None;
    }
    /// The local COMMIT that makes the successor of `previous` visible was acknowledged.
    pub(crate) fn committed(&self, previous: &Head) {
        let mut verified = self.verified.lock().unwrap();
        if verified.in_flight.as_ref().is_some_and(|(head, _)| head == previous) {
            verified.in_flight = None;
        }
        if verified.superseded.len() == 8 {
            verified.superseded.pop_front();
        }
        verified.superseded.push_back(previous.clone());
    }
    /// The witness advanced and the local COMMIT did not: this store is behind its witness
    /// and is refused from now on, without waiting for a lease to run out.
    pub(crate) fn commit_failed(&self, previous: &Head) {
        let mut verified = self.verified.lock().unwrap();
        if verified.in_flight.as_ref().is_some_and(|(head, _)| head == previous) {
            verified.in_flight = None;
        }
    }
}

fn pinned(head: Option<&Head>, configured: Option<uuid::Uuid>) -> Result<(), Error> {
    let expected = match configured {
        Some(expected) => Some(expected),
        None => expected_lineage()?,
    };
    if let Some(expected) = expected {
        if head.map(|h| h.lineage) != Some(expected) {
            return Err(err_msg!(
                Backend,
                "Store freshness binding absent or mismatched"
            ));
        }
    }
    Ok(())
}

/// Admit `head`, freshly read from the store: within the read lease when the witness
/// confirmed exactly this head less than a lease ago, otherwise by asking the witness now.
///
/// The lease never admits a head the witness did not hold: an older copy of the store has an
/// older head, which is not the confirmed one, and is sent to the witness and refused. What
/// the lease gives up is the instant: a store that was current when confirmed and has since
/// been left behind (the real store moved on elsewhere) is served for at most one lease.
pub(crate) async fn check_for(
    head: Option<&Head>,
    configured: Option<uuid::Uuid>,
) -> Result<(), Error> {
    pinned(head, configured)?;
    let Some(head) = head else { return Ok(()) };
    let lineage = Lineage::of(head.lineage);
    let lease = lineage.lease();
    if lease.is_zero() {
        return verify(&lineage, head).await;
    }
    if lineage.leased(head, lease) {
        LEASE_ADMISSIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Ok(());
    }
    let _turn = lineage.flight.lock().await;
    if lineage.leased(head, lease) {
        LEASE_ADMISSIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return Ok(());
    }
    verify(&lineage, head).await
}
/// Admit `head` only on the witness's answer now. Opening a store never uses the lease.
pub(crate) async fn check_fresh(
    head: Option<&Head>,
    configured: Option<uuid::Uuid>,
) -> Result<(), Error> {
    pinned(head, configured)?;
    let Some(head) = head else { return Ok(()) };
    verify(&Lineage::of(head.lineage), head).await
}
async fn verify(lineage: &Lineage, head: &Head) -> Result<(), Error> {
    #[cfg(test)]
    read_race_tests::pause(head).await;
    witness().await?.check(head).await?;
    lineage.confirmed(head);
    Ok(())
}
/// The head a writer commits on is the one it reads under the head lock, not the one it was
/// admitted on: other writers chain commits in between. It must be that admitted head or a
/// later head of the same lineage. A head that went back, or sideways (the same sequence
/// with another token), belongs to another copy of the database. This is a local sanity
/// rule; the proof that the locked head is current is the witness compare-and-advance.
pub(crate) fn continues(
    admitted: &Head,
    locked: &Head,
    configured: Option<uuid::Uuid>,
) -> Result<(), Error> {
    pinned(Some(locked), configured)?;
    if locked.lineage != admitted.lineage {
        return Err(err_msg!(
            Backend,
            "Store freshness binding absent or mismatched"
        ));
    }
    if locked.sequence < admitted.sequence
        || (locked.sequence == admitted.sequence && locked.token != admitted.token)
    {
        return Err(err_msg!(Backend, "Freshness advance refused: stale store"));
    }
    Ok(())
}
#[cfg(feature = "postgres")]
pub(crate) async fn witness() -> Result<PostgresWitness, Error> {
    let uri = std::env::var("ASKAR_FRESHNESS_WITNESS_URL").map_err(|_| {
        err_msg!(
            Backend,
            "Bound store requires independent freshness witness"
        )
    })?;
    type Cell = std::sync::Arc<tokio::sync::OnceCell<PostgresWitness>>;
    static POOLS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, Cell>>,
    > = std::sync::OnceLock::new();
    // The map is held only for the lookup; connecting waits on that URL's own cell.
    let cell = POOLS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .entry(uri.clone())
        .or_default()
        .clone();
    cell.get_or_try_init(|| PostgresWitness::connect(&uri))
        .await
        .cloned()
}
#[cfg(not(feature = "postgres"))]
pub(crate) async fn witness() -> Result<UnavailableWitness, Error> {
    Err(err_msg!(
        Backend,
        "Bound store requires PostgreSQL witness support"
    ))
}
#[cfg(not(feature = "postgres"))]
pub(crate) struct UnavailableWitness;
#[cfg(not(feature = "postgres"))]
impl UnavailableWitness {
    pub(crate) async fn check(&self, _: &Head) -> Result<(), Error> {
        Err(err_msg!(Backend, "Witness unavailable"))
    }
    pub(crate) async fn advance_resolved(&self, _: &Head, _: &Head) -> Result<Advance, Error> {
        Err(err_msg!(Backend, "Witness unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "postgres")]
    #[test]
    fn transport_cannot_downgrade_effective_tls() {
        assert!(
            witness_options("postgres://localhost/test?host=external.invalid&sslmode=disable")
                .is_err()
        );
        assert!(witness_options(
            "postgres://external.invalid/test?sslmode=verify-full&ssl-mode=disable"
        )
        .is_err());
        assert!(witness_options(
            "postgres://external.invalid/test?sslmode=disable&ssl-mode=verify-full"
        )
        .is_err());
        assert!(witness_options("postgres://external.invalid/test?sslmode=prefer").is_err());
        assert!(witness_options("postgres://external.invalid/test?ssl-mode=verify-full").is_ok());
        assert!(witness_options("postgres://127.0.0.1/test?sslmode=disable").is_ok());
    }
    #[test]
    fn heads_distinguish_branches_and_refuse_overflow() {
        let h = Head::initial();
        let a = h.next().unwrap();
        let b = h.next().unwrap();
        assert_eq!(a.sequence, b.sequence);
        assert_ne!(a.token, b.token);
        assert_eq!(Head::decode(&h.encode().unwrap()).unwrap(), h);
        let mut exhausted = h;
        exhausted.sequence = u64::MAX;
        assert!(exhausted.next().is_err());
        assert!(Head::decode("{}").is_err());
    }
}

#[cfg(test)]
#[path = "freshness_read_race_tests.rs"]
mod read_race_tests;

/// How long a non-transactional operation keeps repeating itself behind a confirmed forward
/// head. A live writer advances the witness and then commits locally; the witness is one ahead
/// of the visible local head for exactly that durable COMMIT, which on a loaded host runs to
/// hundreds of milliseconds, and consecutive commits chain such windows. The budget is bounded
/// in time, not in confidence: it never widens what a result may be authorized against.
pub(crate) const READ_RACE_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
const READ_RACE_PAUSE: std::time::Duration = std::time::Duration::from_millis(10);

/// Complete read attempts, 10 ms apart, within [`READ_RACE_BUDGET`]; never a writer lock or
/// witness mutation. Only a confirmed forward head is eligible; outages, missing heads and
/// equal-sequence forks are terminal. A stale clone will exhaust this budget and still refuse.
/// An operation inside a transaction is never repeated; a transaction's admission (the head
/// read and its check, no statement of the caller's) is.
pub(crate) struct ReadRetry {
    deadline: Option<tokio::time::Instant>,
    rereads: u8,
}
impl ReadRetry {
    pub(crate) fn new(in_transaction: bool) -> Self {
        Self {
            deadline: (!in_transaction).then(|| tokio::time::Instant::now() + READ_RACE_BUDGET),
            rereads: 0,
        }
    }
    /// The head just read is one this process has itself committed past: the read raced the
    /// acknowledgement of a local COMMIT. Read it again at once, at most three times, before
    /// asking the witness (which would only answer "moved on").
    pub(crate) fn reread(&mut self, head: Option<&Head>) -> bool {
        let Some(head) = head else { return false };
        if self.rereads >= 3 {
            return false;
        }
        let lineage = Lineage::of(head.lineage);
        if lineage.lease().is_zero() || !lineage.superseded(head) {
            return false;
        }
        self.rereads += 1;
        true
    }
    pub(crate) async fn again(&mut self, error: &Error) -> bool {
        if !error.read_head_moved {
            return false;
        }
        let Some(deadline) = self.deadline else {
            return false;
        };
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(READ_RACE_PAUSE).await;
        true
    }
}
