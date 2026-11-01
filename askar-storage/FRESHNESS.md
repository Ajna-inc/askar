# Independently witnessed store freshness

Canonical implementation: `src/backend/freshness.rs` (heads, witness, read lease), `src/backend/commit.rs` (the commit of a transaction that wrote) and `DbSession` in `src/backend/db_utils.rs` (admission). Identity, Vilko and migration callers share this patched Askar implementation. Account wire records, signing messages, encrypted values and account ownership fences are unchanged. The extra head lives in the SQL `config` table, outside the item migration inventory.

An operator explicitly binds a **trusted-current, quiescent** SQL store through `SqliteBackend::bind_freshness` or `PostgresBackend::bind_freshness`. This registers a random lineage once in an independent PostgreSQL witness and commits its local head. Serving never provisions the witness, registers a missing row, repairs a mismatch, or rewinds a register.

Pin the returned lineage independently in each store's connection URI with `freshness_lineage=<UUID>`. Askar strips that parameter before passing the URI to SQLx and carries it through backend open and sessions. Different databases can have different pins in one process. `ASKAR_FRESHNESS_LINEAGE` is a fallback for deployments with one lineage; do not set it globally for several unrelated stores. A pin is necessary to refuse a pre-binding backup or deleted local metadata. Removing both the pin and the local binding defeats the premise; deployment configuration is part of the trusted restore boundary.

`ASKAR_FRESHNESS_WITNESS_URL` is a separate PostgreSQL credential and restore domain. A second database on a server whose snapshots are restored together is not independence. The effective parsed PostgreSQL host/SSL configuration is checked: non-loopback connections require certificate and hostname verification, Unix sockets are refused, and duplicate `sslmode`/`ssl-mode` aliases cannot downgrade TLS. Credentials and transport errors are not printed. Witness connections set five-second query/lock deadlines and synchronous witness commits. PostgreSQL servers and their disks must provide durable WAL/fsync; restoring the witness with identity is explicitly outside the guarantee.

## The property

1. A copy of the store older than the last acknowledged write is refused: when it is opened, and when a process that has it open reads or writes.
2. Every acknowledged write advanced the witness before its local COMMIT was sent.

The store format is the one bound stores already have: one head row `askar_freshness_head_v1` in `config`, one witness row per lineage. Nothing is re-bound or migrated.

## Admission (reads, and the start of every transaction)

No admission takes a lock on the head. One statement reads the head and the session's profile row (PostgreSQL: a single round trip); the head is then admitted in one of two ways:

- **Witness**: the witness holds exactly this `(lineage, sequence, token)` now.
- **Read lease**: the witness confirmed exactly this head less than one lease ago, in this process. The lease is 1 s by default: `ASKAR_FRESHNESS_READ_LEASE_MS` for the process, `freshness_read_lease_ms=<ms>` in a pinned store's URI for that lineage, `0` to ask the witness on every admission, and after every read outside a transaction. (Before this protocol a transaction also asked after each of its reads, with the head locked; now the head is not locked, so a transaction is checked at each admission and at its commit.) The confirmation is process memory, keyed by the exact head: a new process has none; concurrent admissions on a cold lease share one witness query.

Opening a store never uses the lease.

When each kind of session is admitted:

| Session | Admitted | Profile row |
|---|---|---|
| Outside a transaction | before every operation, and checked again after a read that outlasted the lease (always, with a zero lease) | read every time, not locked |
| Transaction | at its first operation, then only once its admission is older than the lease (every operation, with a zero lease) | locked `FOR NO KEY UPDATE` at the first admission, for the transaction |
| Implicit transaction of a write outside a transaction | when it begins | locked for its length |

What the lease does and does not give up:

- An **older copy** (a restore) has an older head. An older head is never the confirmed head, whatever the lease: the witness is asked and the copy is refused. A session outside a transaction reads the head on every operation, so it refuses on its next operation; a transaction that was already admitted on the genuine head refuses no later than one lease after that admission and cannot commit (below).
- A **fork** is what the lease trades. A process attached to a database that was current when confirmed, while the real store has since moved on elsewhere (another writer on another database of the same lineage), serves reads on its unchanged head for at most one lease after its last confirmation, then for at most the forward-race budget (2 s), and is then refused. Writes never use the lease: every commit is a compare-and-advance at the witness, so a forked store cannot commit at all.
- A head one behind the witness is also what a live store looks like for the length of another writer's local COMMIT. Admission repeats itself (the head read and its check, never a statement of the caller's), 10 ms apart, for at most two seconds (`READ_RACE_BUDGET`), only when an existing, valid witness head has moved forward. Missing heads, outages, malformed heads, equal-sequence token mismatches and profile identity changes are terminal. Stale clones exhaust the same budget and still refuse. While the witness is unreachable, admissions on a cold lease of one lineage fail one after another (each can wait up to 10 s for the witness), not in parallel. In the committing process itself no such wait occurs: it knows which head it is moving past.

Operations outside a transaction (`fetch`, `count`, fully collected `fetch_all`, the profile list, the default profile) repeat the complete operation on such a forward race, and discard the prior encrypted and decrypted results. Explicit transactions and externally streamed scans never restart: only their admission does.

### The profile-key cache

A bound store uses the profile-key cache again. Every admission reads the profile row; the cached key is used only when that row has the profile id and the SHA-256 of the wrapped key the cached key was unwrapped from. A profile that was removed and created again, with the same name or (SQLite) the same id, has another wrapped key, so it is unwrapped afresh; a session that was using the old profile is refused ("Session profile has been removed", "Session profile key changed"). The cache therefore needs no invalidation on a head or lineage change: it never answers for a row it has not just seen. Inside a transaction the row is locked and is read once.

## Commit

Read-only transactions, rollbacks and clean commits touch neither the head nor the witness. A transaction is dirty from its first mutating statement. The outermost commit of a dirty transaction on a bound store is handed to the backend's committer (`commit.rs`):

1. `SELECT value … FOR UPDATE` on the head row, in the committing transaction. This is the only place the head is locked. PostgreSQL returns the latest committed head once the lock is granted, so the value read is the true predecessor. The same statement makes the transaction's COMMIT synchronous.
2. The locked head must continue the head the writer was admitted on: the same lineage, and either the same head or a later one (other writers chained commits meanwhile). A head that went back, or sideways (same sequence, another token), is refused. This is a local sanity rule; the proof is step 4.
3. The next head (sequence + 1, a fresh random token) is written in the same transaction.
4. Compare-and-advance at the witness, from the locked head to the next head. It succeeds only if the witness holds exactly the locked head, which is what makes it the freshness check of the commit: a stale or forked store cannot pass it.
5. Local COMMIT.

The head lock is held from step 1 to step 5: one head write, one witness round trip, one COMMIT. It is never held across the caller's work. Lock order is profile row, then head; the head is the last lock taken. A committer that cannot take the head within `ASKAR_FRESHNESS_COMMIT_LOCK_WAIT_MS` (default 10 s) fails with "Freshness head busy", having changed nothing outside its own transaction, which is rolled back.

### Commits that wait together share one advance

Commits of one process that reach the committer while an advance is in flight form the next batch. The first is the leader: it does steps 1 to 4 in its own transaction. Then every other transaction of the batch (a follower, which never touches the head row) sends its COMMIT, all at once; when all of those have settled, the leader sends its COMMIT; then every caller is answered. Three orderings carry the property:

- The witness is advanced before any local COMMIT of the batch. A copy that lacks an acknowledged write of the batch has the old head or an older one, behind the witness.
- The leader's COMMIT, which makes the new head visible, comes after every follower's COMMIT has settled. A copy that shows the new head holds every write acknowledged under it.
- No caller is answered before the leader's COMMIT has been attempted.

A follower's COMMIT that fails fails only that transaction. A follower's COMMIT that is not acknowledged within 30 s is reported as failed although it may still land; it was never acknowledged, so the property is not affected. Commits of other processes wait on the head row lock and chain. `ASKAR_FRESHNESS_GROUP_COMMIT=0` gives every commit its own advance.

The batch runs on its own task, on the crate's runtime rather than the caller's, and owns the connections of its transactions until every outcome is known. A caller that stops waiting (a timeout around the transaction, a dropped request) cannot stop a commit between the witness advance and the local COMMIT; its session is unusable afterwards and the commit finishes or fails as one piece.

### Throughput

`L` is a store round trip, `W` a witness round trip, `Fs` and `Fw` the WAL flushes of the store and of the witness. The head is held for

`C = L + (W + Fw) + (L + Fs) + (L + Fs)` (head write, advance, followers' COMMITs in parallel, leader's COMMIT; `2L + W + Fw + Fs` for a commit on its own).

The store, across all processes, completes at most `1 / C` advances per second, and one process commits up to `B` transactions per advance, where `B` is the number of transactions waiting to commit (at most 256, and at most one per profile unless the store was opened with `profile_lock=key_share`, because transactions of one profile otherwise run one after another on the profile row lock):

`commits per second ≤ min(256, profiles committing at once, store pool size) / (3L + W + Fw + 2Fs)`.

Reads and read-only transactions are outside this: they take no lock and, within the lease, send nothing to the witness.

## When the witness could be ahead of the store

The witness is advanced before the local COMMIT, so there are moments when it is one ahead. What happens to each:

| Situation | Outcome |
|---|---|
| The compare-and-advance was sent and no answer came (deadline, lost connection) | Never assumed failed. The identical statement is sent again, up to three more times. `next.token` is random and known only to this commit, and the witness row serializes the statements, so once any attempt answers the witness holds `next` exactly when one of them applied: an attempt that changes the row, or one that changes nothing while the witness holds exactly `next`, means applied and the commit goes on; one that changes nothing while the witness holds anything else means refused (stale store), and nothing was advanced on this commit's behalf |
| The caller stopped waiting during the commit | The committer finishes it (above) |
| No attempt was answered at all (the witness is unreachable for the whole retry) | The batch is rolled back and the pair `(previous, next)` is remembered by the process. The witness may hold `next`. The next commit that locks the head and finds exactly `previous` makes that same advance again, with the same token, as its own: the statement is idempotent, so the witness holds `next` whichever of them it applied, and the locked head proves no transaction of the first batch committed. Reads are refused in between once their lease is over. A process restart forgets the pair, and the store is then refused until the operator recovers it |
| The witness advanced and the leader's local COMMIT then failed | Unchanged: nothing rewinds the witness, the store is refused from then on (at once, not after the lease), and recovery is the operator's, after independently verified replay. Followers of that batch that did commit are in the refused store |
| The process died between the advance and the local COMMIT | Unchanged: the store is refused at the next open. Removing this window needs a two-phase local commit (`PREPARE TRANSACTION`, advance, `COMMIT PREPARED`, with recovery deciding from the witness), which needs `max_prepared_transactions > 0` and a second local flush per advance; not implemented |

## Sessions and profiles

Bound sessions pin the profile id, name and wrapped-key fingerprint, and validate that identity on each admission. A session outside a transaction reads the committed rows without row locks (an autocommit row lock would end with the statement and protect nothing), so it never queues behind a transaction, including one that it is serving from another connection. Removing and recreating a profile cannot revive an old session, including SQLite profile-ID reuse. SQLite metadata checks require durable synchronous and journal settings.

### The profile row lock

A transaction locks its profile row until it ends. By default the lock is `FOR NO KEY UPDATE`, as in upstream Askar. It keeps the profile from being removed under the transaction, and because it conflicts with itself it also makes the transactions of one profile run strictly one after another, on every process. Callers can rely on that: a transaction that reads a record with a plain fetch and then replaces it cannot lose an update to another transaction of the same profile. On a store with one profile it serializes every transaction.

`profile_lock=key_share` in a PostgreSQL store's URI takes `FOR KEY SHARE` instead. Removal is still held off (a DELETE needs the row `FOR UPDATE`, which conflicts with a key share), and so is a rename (the name is a unique key). The profile's transactions then overlap under READ COMMITTED. That is safe only for a store whose read-modify-write transactions read `for_update` (which locks the item rows) or are serialized by the caller; a plain fetch followed by a replace can lose an update. A rekey is no longer held off either; it rewrites the wrapped key and leaves the profile key itself unchanged, and a bound store refuses rekey and rename in any case. It is therefore an opt-in per store, not the default. SQLite has one writer at a time and ignores it.

## Supported and refused paths

| Existing path | Bound-store behavior |
| --- | --- |
| Explicit item insert, replace, remove, bulk deletion | Guarded final commit |
| Implicit item insert/replace | Guarded internal outer transaction |
| Implicit remove/bulk deletion | Guarded internal outer transaction |
| Profile create/remove | Metadata-only session using the same guarded admission/commit protocol |
| Profile rename/default change, rekey | Refused before mutation |
| SQL recreation or database removal | Refused before destructive work |
| Profile reads, open, item reads, scans | Freshness admission |
| Flat-file backend | Refused in a freshness-configured deployment |
| Direct Indy-SDK SQL upgrade | Refused in a freshness-configured deployment |
| Copy/import into another store | Destination requires its own trusted-current binding and independently pinned lineage before serving |

These refusals are intentional compatibility limits, not unguarded exceptions. Applications that require profile renaming, default-profile changes or rekey must extend this canonical protocol before enabling those lifecycle operations. Vilko tenant creation/removal, root/room-log bootstrap and mediator implicit deletion use the supported paths. Pinned TenantStore opens never fall back to provisioning after a freshness refusal.

## Configuration

| Setting | Default | Meaning |
|---|---|---|
| `ASKAR_FRESHNESS_READ_LEASE_MS`, `freshness_read_lease_ms` (URI, needs the pin) | 1000 | Read lease; 0 asks the witness every time |
| `ASKAR_FRESHNESS_WITNESS_POOL` | 8 | Size of the witness read pool and of the advance pool (connections are opened on demand) |
| `ASKAR_FRESHNESS_COMMIT_LOCK_WAIT_MS` | 10000 | Longest wait for the head row at commit |
| `ASKAR_FRESHNESS_GROUP_COMMIT` | on | `0`: one advance per commit |
| `profile_lock` (URI, PostgreSQL) | `no_key_update` | `key_share`: transactions of one profile overlap (see "The profile row lock") |

`backend::freshness::fence_stats()` counts witness checks, compare-and-advance statements, lease admissions, advances and the commits they carried.

## Rolling out beside the earlier protocol

A binary with the earlier protocol locks the head and then the profile row; this one locks the profile row and then, at commit, the head. Two such binaries on one database can deadlock; PostgreSQL aborts one after `deadlock_timeout`, always before its compare-and-advance, so the abort is clean. Replace the processes rather than running both.

## Not done: one head per profile

With one head per profile and one witness row per `(lineage, profile)`, commits of different tenants would share nothing. It was not done:

- An already-bound store has one head and one witness row. Per-profile heads need a quiescent re-bind of every profile, a new witness schema and new pin semantics; they cannot be added to a bound store compatibly, because a binary that checks only the store head would admit a copy whose profiles are old.
- The property changes from "an older copy of the store is refused" to "an older copy is refused for the profiles that wrote since it was taken", and records that span profiles (the root profile's records about a tenant, and the tenant's own) lose their common freshness point.
- Serving would have to register witness rows (at profile creation), which the present design never does.

After this change tenants share one thing at commit: a head advance of `3L + W + Fw + 2Fs` that carries every commit waiting at that moment. Per-profile heads become worth their cost only if that advance, with full batches, is measured to be the ceiling.

## Verification

`tests/freshness_perf.rs`, `tests/freshness_cost.rs` and `tests/freshness_batch.rs` run against a disposable PostgreSQL named by `AJNA_FRESHNESS_TEST_PG_URL` and are skipped without it; the cost test also needs `pg_stat_statements` preloaded. They hold: no head lock for read-only work, no cross-tenant wait behind a transaction that is waiting on I/O, 8 tenants × 4 writers within a parallel bound, shared advances, statement ceilings (plain fetch 3 store statements and no witness query; a read-only transaction with k reads 3 + k and none; one read and one write 7 and 1), single-flight cold checks, the bounded head-lock wait, the resolved ambiguous advance, the abandoned commit, and the refusals: an older copy at open, an older head under a warm lease, a stale writer at commit, a store behind its witness after its lease, a recreated profile, and a failed local COMMIT after the advance. `tests/profile_lock.rs` holds the default and the shared profile lock. The env-gated tests in `src/backend/freshness_read_race_tests.rs` (zero lease) cover the read races on both SQL backends, the lost answer of an advance, and the unanswered advance that the next commit completes.

Earlier evidence still stands for what did not change: the isolated main reconciliation passed the two head/TLS unit tests, 27 SQLite backend regressions, standalone SQLite/PostgreSQL/flat-file feature builds, and the identity operator binary check. The Docker witness acceptance (`scripts/identity/docker/freshness.py`) asserts immediate refusal of an already-open stale clone's read, which now holds only with a zero lease; run it with `ASKAR_FRESHNESS_READ_LEASE_MS=0` or let it wait out the lease. Do not infer an exhaustive fault or production rollout claim from this library implementation.
