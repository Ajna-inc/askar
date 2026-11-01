use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use async_stream::try_stream;

use futures_lite::{
    pin,
    stream::{Stream, StreamExt},
};

use sqlx::{
    postgres::{PgPool, Postgres},
    Acquire, Row, TransactionManager,
};

use super::{
    commit::Committer,
    db_recovery::reset_depth,
    db_utils::{
        decode_tags, decrypt_scan_batch, encode_profile_key, encode_tag_filter, expiry_timestamp,
        extend_query, prepare_tags, random_profile_name, replace_arg_placeholders, Admitted,
        Connection, DbSession, DbSessionActive, DbSessionRef, DbSessionTxn, EncScanEntry,
        ExtDatabase, ProfileLock, ProfileRef, QueryParams, QueryPrepare, PAGE_SIZE,
    },
    Backend, BackendSession,
};
use crate::{
    backend::OrderBy,
    entry::{EncEntryTag, Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter},
    error::Error,
    future::{unblock, BoxFuture},
    protect::{EntryEncryptor, KeyCache, PassKey, ProfileId, ProfileKey, StoreKeyMethod},
};

mod provision;
pub use self::provision::PostgresStoreOptions;

#[cfg(any(test, feature = "pg_test"))]
mod test_db;
#[cfg(any(test, feature = "pg_test"))]
pub use self::test_db::TestDB;

const CONFIG_FETCH_QUERY: &str = "SELECT value FROM config WHERE name = $1";
const ADMIT_BY_NAME_QUERY: &str = "SELECT (SELECT value FROM config WHERE name = $1),
    id, name, profile_key FROM profiles WHERE name = $2";
const ADMIT_BY_ID_QUERY: &str = "SELECT (SELECT value FROM config WHERE name = $1),
    id, name, profile_key FROM profiles WHERE id = $2";
const CONFIG_UPDATE_QUERY: &str = "INSERT INTO config (name, value) VALUES ($1, $2)
    ON CONFLICT(name) DO UPDATE SET value = excluded.value";
const COUNT_QUERY: &str = "SELECT COUNT(*) FROM items i
    WHERE profile_id = $1
    AND (kind = $2 OR $2 IS NULL)
    AND (category = $3 OR $3 IS NULL)
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const DELETE_QUERY: &str = "DELETE FROM items
    WHERE profile_id = $1 AND kind = $2 AND category = $3 AND name = $4";
const FETCH_QUERY: &str = "SELECT id, value,
    (SELECT ARRAY_TO_STRING(ARRAY_AGG(it.plaintext || ':'
        || ENCODE(it.name, 'hex') || ':' || ENCODE(it.value, 'hex')), ',')
        FROM items_tags it WHERE it.item_id = i.id) tags
    FROM items i
    WHERE profile_id = $1 AND kind = $2 AND category = $3 AND name = $4
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const FETCH_QUERY_UPDATE: &str = "SELECT id, value,
    (SELECT ARRAY_TO_STRING(ARRAY_AGG(it.plaintext || ':'
        || ENCODE(it.name, 'hex') || ':' || ENCODE(it.value, 'hex')), ',')
        FROM items_tags it WHERE it.item_id = i.id) tags
    FROM items i
    WHERE profile_id = $1 AND kind = $2 AND category = $3 AND name = $4
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP) FOR NO KEY UPDATE";
const INSERT_QUERY: &str = "INSERT INTO items (profile_id, kind, category, name, value, expiry)
    VALUES ($1, $2, $3, $4, $5, $6)
    ON CONFLICT DO NOTHING RETURNING id";
const UPDATE_QUERY: &str = "UPDATE items SET value=$5, expiry=$6
    WHERE profile_id=$1 AND kind=$2 AND category=$3 AND name=$4
    RETURNING id";
const SCAN_QUERY: &str = "SELECT id, kind, category, name, value,
    (SELECT ARRAY_TO_STRING(ARRAY_AGG(it.plaintext || ':'
        || ENCODE(it.name, 'hex') || ':' || ENCODE(it.value, 'hex')), ',')
        FROM items_tags it WHERE it.item_id = i.id) tags
    FROM items i WHERE profile_id = $1
    AND (kind = $2 OR $2 IS NULL)
    AND (category = $3 OR $3 IS NULL)
    AND (expiry IS NULL OR expiry > CURRENT_TIMESTAMP)";
const DELETE_ALL_QUERY: &str = "DELETE FROM items i
    WHERE profile_id = $1
    AND (kind = $2 OR $2 IS NULL)
    AND (category = $3 OR $3 IS NULL)";
const TAG_INSERT_QUERY: &str = "INSERT INTO items_tags
    (item_id, name, value, plaintext) VALUES ($1, $2, $3, $4)";
const TAG_DELETE_QUERY: &str = "DELETE FROM items_tags
    WHERE item_id=$1";

/// A PostgreSQL database store
pub struct PostgresBackend {
    conn_pool: PgPool,
    active_profile: String,
    key_cache: Arc<KeyCache>,
    expected_freshness: Option<uuid::Uuid>,
    committer: Committer<Postgres>,
    profile_lock: ProfileLock,
    host: String,
    name: String,
}

impl PostgresBackend {
    pub(crate) fn with_freshness_lineage(mut self, expected: Option<uuid::Uuid>) -> Self {
        self.expected_freshness = expected;
        self
    }
    pub(crate) fn with_profile_lock(mut self, lock: ProfileLock) -> Self {
        self.profile_lock = lock;
        self
    }

    async fn check_freshness(&self) -> Result<(), Error> {
        let mut conn = self.conn_pool.acquire().await?;
        let mut retry = super::freshness::ReadRetry::new(false);
        loop {
            let head = <Postgres as ExtDatabase>::freshness_head(&mut conn, false).await?;
            if retry.reread(head.as_ref()) {
                continue;
            }
            match super::freshness::check_for(head.as_ref(), self.expected_freshness).await {
                Ok(()) => return Ok(()),
                Err(error) if retry.again(&error).await => continue,
                Err(error) => return Err(error),
            }
        }
    }
    async fn refuse_bound_mutation(&self) -> Result<(), Error> {
        let mut conn = self.conn_pool.acquire().await?;
        let head = <Postgres as ExtDatabase>::freshness_head(&mut conn, false).await?;
        super::freshness::check_for(head.as_ref(), self.expected_freshness).await?;
        if head.is_some() {
            return Err(err_msg!(
                Backend,
                "Bound store profile and rekey operations are not supported"
            ));
        }
        Ok(())
    }
    /// Explicit trusted-current bootstrap. Stop all writers and retain returned lineage
    /// independently in deployment configuration before serving. Never call on startup.
    #[cfg(feature = "postgres")]
    pub async fn bind_freshness(
        &self,
        witness: &super::freshness::PostgresWitness,
    ) -> Result<super::freshness::Head, Error> {
        let mut conn = self.conn_pool.acquire().await?;
        <Postgres as ExtDatabase>::start_transaction(&mut conn, false).await?;
        let result = async {
            if <Postgres as ExtDatabase>::freshness_head(&mut conn, true)
                .await?
                .is_some()
            {
                return Err(err_msg!(Backend, "Store already bound"));
            }
            let head = super::freshness::Head::initial();
            witness.register(&head).await?;
            <Postgres as ExtDatabase>::freshness_write(&mut conn, &head).await?;
            <Postgres as sqlx::Database>::TransactionManager::commit(&mut conn).await?;
            Ok(head)
        }
        .await;
        if result.is_err() {
            <Postgres as sqlx::Database>::TransactionManager::start_rollback(&mut conn);
        }
        result
    }

    pub(crate) fn new(
        conn_pool: PgPool,
        active_profile: String,
        key_cache: KeyCache,
        host: String,
        name: String,
    ) -> Self {
        Self {
            conn_pool,
            active_profile,
            key_cache: Arc::new(key_cache),
            expected_freshness: None,
            committer: Committer::default(),
            profile_lock: ProfileLock::default(),
            host,
            name,
        }
    }
}

impl Backend for PostgresBackend {
    type Session = DbSession<Postgres>;

    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String, Error>> {
        let name = name.unwrap_or_else(random_profile_name);
        Box::pin(async move {
            let store_key = self.key_cache.store_key.clone();
            let (profile_key, enc_key) = unblock(move || {
                let profile_key = ProfileKey::new()?;
                let enc_key = encode_profile_key(&profile_key, &store_key)?;
                Result::<_, Error>::Ok((profile_key, enc_key))
            })
            .await?;
            let mut tx = self.session(None, true)?;
            let conn = tx.metadata_connection().await?;
            let res = sqlx::query_scalar(
                "INSERT INTO profiles (name, profile_key) VALUES ($1, $2)
                ON CONFLICT DO NOTHING RETURNING id",
            )
            .bind(&name)
            .bind(enc_key)
            .fetch_optional(conn)
            .await?;
            if let Some(pid) = res {
                tx.freshness_dirty = true;
                tx.close(true).await?;
                self.key_cache
                    .add_profile(name.clone(), pid, Arc::new(profile_key))
                    .await;
                Ok(name)
            } else {
                tx.close(false).await?;
                Err(err_msg!(Duplicate, "Duplicate profile name"))
            }
        })
    }

    fn get_active_profile(&self) -> String {
        self.active_profile.clone()
    }

    fn get_default_profile(&self) -> BoxFuture<'_, Result<String, Error>> {
        Box::pin(async move {
            self.check_freshness().await?;
            let mut conn = self.conn_pool.acquire().await?;
            let profile: Option<String> = sqlx::query_scalar(CONFIG_FETCH_QUERY)
                .bind("default_profile")
                .fetch_one(conn.as_mut())
                .await
                .map_err(err_map!(Backend, "Error fetching default profile name"))?;
            conn.return_to_pool().await;
            self.check_freshness().await?;
            Ok(profile.unwrap_or_default())
        })
    }

    fn set_default_profile(&self, profile: String) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.refuse_bound_mutation().await?;
            let mut conn = self.conn_pool.acquire().await?;
            sqlx::query(CONFIG_UPDATE_QUERY)
                .bind("default_profile")
                .bind(profile)
                .execute(conn.as_mut())
                .await
                .map_err(err_map!(Backend, "Error setting default profile name"))?;
            conn.return_to_pool().await;
            Ok(())
        })
    }

    fn list_profiles(&self) -> BoxFuture<'_, Result<Vec<String>, Error>> {
        Box::pin(async move {
            self.check_freshness().await?;
            let mut conn = self.conn_pool.acquire().await?;
            let rows = sqlx::query("SELECT name FROM profiles")
                .fetch_all(conn.as_mut())
                .await
                .map_err(err_map!(Backend, "Error fetching profile list"))?;
            let names = rows.into_iter().flat_map(|r| r.try_get(0)).collect();
            conn.return_to_pool().await;
            self.check_freshness().await?;
            Ok(names)
        })
    }

    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>> {
        Box::pin(async move {
            let mut tx = self.session(None, true)?;
            let conn = tx.metadata_connection().await?;
            let ret = sqlx::query("DELETE FROM profiles WHERE name=$1")
                .bind(&name)
                .execute(conn)
                .await
                .map_err(err_map!(Backend, "Error removing profile"))?
                .rows_affected()
                != 0;
            tx.freshness_dirty = ret;
            tx.close(ret).await?;
            self.key_cache.clear_profile(&name).await;
            Ok(ret)
        })
    }

    fn rename_profile(
        &self,
        from_name: String,
        to_name: String,
    ) -> BoxFuture<'_, Result<bool, Error>> {
        Box::pin(async move {
            self.refuse_bound_mutation().await?;
            let mut conn = self.conn_pool.acquire().await?;
            let ret = sqlx::query("UPDATE profiles SET name=$1 WHERE name=$2")
                .bind(&to_name)
                .bind(&from_name)
                .execute(conn.as_mut())
                .await
                .map_err(err_map!(Backend, "Error renaming profile"))?
                .rows_affected()
                != 0;
            conn.return_to_pool().await;
            self.key_cache.clear_profile(&from_name).await;
            Ok(ret)
        })
    }

    fn rekey(
        &mut self,
        method: StoreKeyMethod,
        pass_key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        let pass_key = pass_key.into_owned();
        Box::pin(async move {
            self.refuse_bound_mutation().await?;
            let (store_key, store_key_ref) = unblock(move || method.resolve(pass_key)).await?;
            let store_key = Arc::new(store_key);
            let mut conn = self.conn_pool.acquire().await?;
            let mut txn = conn.begin().await?;
            let mut rows = sqlx::query("SELECT id, profile_key FROM profiles").fetch(txn.as_mut());
            let mut upd_keys = BTreeMap::<ProfileId, Vec<u8>>::new();
            while let Some(row) = rows.next().await {
                let row = row?;
                let pid = row.try_get(0)?;
                let enc_key = row.try_get(1)?;
                let profile_key = self.key_cache.load_key(enc_key).await?;
                let upd_key = unblock({
                    let store_key = store_key.clone();
                    move || encode_profile_key(&profile_key, &store_key)
                })
                .await?;
                upd_keys.insert(pid, upd_key);
            }
            drop(rows);
            for (pid, key) in upd_keys {
                if sqlx::query("UPDATE profiles SET profile_key=$1 WHERE id=$2")
                    .bind(key)
                    .bind(pid)
                    .execute(txn.as_mut())
                    .await?
                    .rows_affected()
                    != 1
                {
                    return Err(err_msg!(Backend, "Error updating profile key"));
                }
            }
            if sqlx::query("UPDATE config SET value=$1 WHERE name='key'")
                .bind(store_key_ref.into_uri())
                .execute(txn.as_mut())
                .await?
                .rows_affected()
                != 1
            {
                return Err(err_msg!(Backend, "Error updating store key"));
            }
            txn.commit().await?;
            conn.return_to_pool().await;
            self.key_cache = Arc::new(KeyCache::new(store_key));
            Ok(())
        })
    }

    fn scan(
        &self,
        profile: Option<String>,
        kind: Option<EntryKind>,
        category: Option<String>,
        tag_filter: Option<TagFilter>,
        offset: Option<i64>,
        limit: Option<i64>,
        order_by: Option<OrderBy>,
        descending: bool,
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>, Error>> {
        Box::pin(async move {
            let session = self.session(profile, false)?;
            let mut active = session.owned_ref();
            let (profile_id, key) = acquire_key(&mut active).await?;
            let scan = perform_scan(
                active,
                profile_id,
                key.clone(),
                kind,
                category.clone(),
                tag_filter,
                offset,
                limit,
                order_by,
                descending,
                false,
            );
            let stream = scan.then(move |enc_rows| {
                let category = category.clone();
                let key = key.clone();
                unblock(move || decrypt_scan_batch(category, enc_rows?, &key))
            });
            Ok(Scan::new(stream, PAGE_SIZE))
        })
    }

    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session, Error> {
        Ok(DbSession::new(
            self.conn_pool.clone(),
            self.key_cache.clone(),
            profile.unwrap_or_else(|| self.active_profile.clone()),
            transaction,
        )
        .with_freshness_lineage(self.expected_freshness)
        .with_profile_lock(self.profile_lock)
        .with_committer(self.committer.clone()))
    }

    fn close(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.conn_pool.close().await;
            Ok(())
        })
    }
}

impl Debug for PostgresBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresStore")
            .field("active_profile", &self.active_profile)
            .field("host", &self.host)
            .field("name", &self.name)
            .finish()
    }
}

impl BackendSession for DbSession<Postgres> {
    fn count<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        let category = category.map(str::to_owned);

        Box::pin(async move {
            let mut retry = super::freshness::ReadRetry::new(self.in_transaction());
            loop {
                let result = async {
                    let enc_category = category
                        .as_ref()
                        .map(|c| ProfileKey::prepare_input(c.as_bytes()));
                    let tag_filter = tag_filter.clone();
                    let (profile_id, key) = acquire_key(&mut *self).await?;
                    let mut params = QueryParams::new();
                    params.push(profile_id);
                    params.push(kind.map(|k| k as i16));
                    let (enc_category, tag_filter) = unblock({
                        let params_len = params.len() + 1; // plus category
                        move || {
                            Result::<_, Error>::Ok((
                                enc_category
                                    .map(|c| key.encrypt_entry_category(c))
                                    .transpose()?,
                                encode_tag_filter::<PostgresBackend>(tag_filter, &key, params_len)?,
                            ))
                        }
                    })
                    .await?;
                    params.push(enc_category);
                    let query = extend_query::<PostgresBackend>(
                        COUNT_QUERY,
                        &mut params,
                        tag_filter,
                        None,
                        None,
                        None,
                        false,
                    )?;
                    let mut active = acquire_session(&mut *self).await?;
                    let count = sqlx::query_scalar_with(query.as_str(), params)
                        .fetch_one(active.connection_mut())
                        .await
                        .map_err(err_map!(Backend, "Error performing count query"))?;
                    active.check_read().await?;
                    Ok(count)
                }
                .await;
                match result {
                    Err(error) if retry.again(&error).await => continue,
                    result => return result,
                }
            }
        })
    }

    fn fetch(
        &mut self,
        kind: EntryKind,
        category: &str,
        name: &str,
        for_update: bool,
    ) -> BoxFuture<'_, Result<Option<Entry>, Error>> {
        let category = category.to_string();
        let name = name.to_string();

        Box::pin(async move {
            let mut retry = super::freshness::ReadRetry::new(self.in_transaction());
            loop {
                let result = async {
                    let category = category.clone();
                    let name = name.clone();
                    let (profile_id, key) = acquire_key(&mut *self).await?;
                    let (enc_category, enc_name) = unblock({
                        let key = key.clone();
                        let category = ProfileKey::prepare_input(category.as_bytes());
                        let name = ProfileKey::prepare_input(name.as_bytes());
                        move || {
                            Result::<_, Error>::Ok((
                                key.encrypt_entry_category(category)?,
                                key.encrypt_entry_name(name)?,
                            ))
                        }
                    })
                    .await?;
                    let mut active = acquire_session(&mut *self).await?;
                    if let Some(row) = sqlx::query(if for_update && active.in_transaction() {
                        FETCH_QUERY_UPDATE
                    } else {
                        FETCH_QUERY
                    })
                    .bind(profile_id)
                    .bind(kind as i16)
                    .bind(enc_category)
                    .bind(enc_name)
                    .fetch_optional(active.connection_mut())
                    .await
                    .map_err(err_map!(Backend, "Error performing fetch query"))?
                    {
                        let value = row.try_get(1)?;
                        let tags = row.try_get::<Option<String>, _>(2)?.map(String::into_bytes);
                        let (category, name, value, tags) = unblock(move || {
                            let value =
                                key.decrypt_entry_value(category.as_ref(), name.as_ref(), value)?;
                            let tags = if let Some(enc_tags) = tags {
                                key.decrypt_entry_tags(
                                    decode_tags(enc_tags)
                                        .map_err(|_| err_msg!(Unexpected, "Error decoding tags"))?,
                                )?
                            } else {
                                Vec::new()
                            };
                            Result::<_, Error>::Ok((category, name, value, tags))
                        })
                        .await?;
                        active.check_read().await?;
                        Ok(Some(Entry::new(kind, category, name, value, tags)))
                    } else {
                        active.check_read().await?;
                        Ok(None)
                    }
                }
                .await;
                match result {
                    Err(error) if retry.again(&error).await => continue,
                    result => return result,
                }
            }
        })
    }

    fn fetch_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        order_by: Option<OrderBy>,
        descending: bool,
        for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>, Error>> {
        let category = category.map(|c| c.to_string());
        Box::pin(async move {
            let mut retry = super::freshness::ReadRetry::new(self.in_transaction());
            loop {
                let result = async {
                    let category = category.clone();
                    let tag_filter = tag_filter.clone();
                    let for_update = for_update && self.in_transaction();
                    let rows = {
                        let mut active = self.borrow_mut();
                        let (profile_id, key) = acquire_key(&mut active).await?;
                        let scan = perform_scan(
                            active,
                            profile_id,
                            key.clone(),
                            kind,
                            category.clone(),
                            tag_filter,
                            None,
                            limit,
                            order_by,
                            descending,
                            for_update,
                        );
                        pin!(scan);
                        let mut enc_rows = vec![];
                        while let Some(rows) = scan.try_next().await? {
                            enc_rows.extend(rows)
                        }
                        unblock(move || decrypt_scan_batch(category, enc_rows, &key)).await?
                    };
                    self.validate_read_head().await?;
                    Ok(rows)
                }
                .await;
                match result {
                    Err(error) if retry.again(&error).await => continue,
                    result => return result,
                }
            }
        })
    }

    fn remove_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        let enc_category = category.map(|c| ProfileKey::prepare_input(c.as_bytes()));

        Box::pin(async move {
            let (profile_id, key) = acquire_key(&mut *self).await?;
            let mut params = QueryParams::new();
            params.push(profile_id);
            params.push(kind.map(|k| k as i16));
            let (enc_category, tag_filter) = unblock({
                let params_len = params.len() + 1; // plus category
                move || {
                    Result::<_, Error>::Ok((
                        enc_category
                            .map(|c| key.encrypt_entry_category(c))
                            .transpose()?,
                        encode_tag_filter::<PostgresBackend>(tag_filter, &key, params_len)?,
                    ))
                }
            })
            .await?;
            params.push(enc_category);
            let query = extend_query::<PostgresBackend>(
                DELETE_ALL_QUERY,
                &mut params,
                tag_filter,
                None,
                None,
                None,
                false,
            )?;

            let mut active = acquire_session(&mut *self).await?;
            let mut txn = active.as_transaction().await?;
            let removed = sqlx::query_with(query.as_str(), params)
                .execute(txn.connection_mut())
                .await?
                .rows_affected();
            if removed != 0 {
                txn.mark_dirty();
            }
            txn.commit().await?;
            Ok(removed as i64)
        })
    }

    fn update<'q>(
        &'q mut self,
        kind: EntryKind,
        operation: EntryOperation,
        category: &'q str,
        name: &'q str,
        value: Option<&'q [u8]>,
        tags: Option<&'q [EntryTag]>,
        expiry_ms: Option<i64>,
    ) -> BoxFuture<'q, Result<(), Error>> {
        let category = ProfileKey::prepare_input(category.as_bytes());
        let name = ProfileKey::prepare_input(name.as_bytes());

        match operation {
            op @ EntryOperation::Insert | op @ EntryOperation::Replace => {
                let value = ProfileKey::prepare_input(value.unwrap_or_default());
                let tags = tags.map(prepare_tags);
                Box::pin(async move {
                    let (_, key) = acquire_key(&mut *self).await?;
                    let (enc_category, enc_name, enc_value, enc_tags) = unblock(move || {
                        let enc_value =
                            key.encrypt_entry_value(category.as_ref(), name.as_ref(), value)?;
                        Result::<_, Error>::Ok((
                            key.encrypt_entry_category(category)?,
                            key.encrypt_entry_name(name)?,
                            enc_value,
                            tags.transpose()?
                                .map(|t| key.encrypt_entry_tags(t))
                                .transpose()?,
                        ))
                    })
                    .await?;
                    self.freshness_dirty = true;
                    let mut active = acquire_session(&mut *self).await?;
                    let mut txn = active.as_transaction().await?;
                    perform_insert(
                        &mut txn,
                        kind,
                        &enc_category,
                        &enc_name,
                        &enc_value,
                        enc_tags,
                        expiry_ms,
                        op == EntryOperation::Insert,
                    )
                    .await?;
                    txn.commit().await?;
                    Ok(())
                })
            }

            EntryOperation::Remove => Box::pin(async move {
                let (_, key) = acquire_key(&mut *self).await?;
                let (enc_category, enc_name) = unblock(move || {
                    Result::<_, Error>::Ok((
                        key.encrypt_entry_category(category)?,
                        key.encrypt_entry_name(name)?,
                    ))
                })
                .await?;
                let mut active = acquire_session(&mut *self).await?;
                let mut txn = active.as_transaction().await?;
                perform_remove(&mut txn, kind, &enc_category, &enc_name, false).await?;
                txn.mark_dirty();
                txn.commit().await?;
                Ok(())
            }),
        }
    }

    fn ping(&mut self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            let mut sess = acquire_session(&mut *self).await?;
            if sess.in_transaction() {
                // the profile row is locked, perform a typical ping
                sqlx::Connection::ping(sess.connection_mut())
                    .await
                    .map_err(err_map!(Backend, "Error pinging session"))?;
            } else if !sess.profile_checked() {
                let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM profiles WHERE id=$1")
                    .bind(sess.profile_id)
                    .fetch_one(sess.connection_mut())
                    .await
                    .map_err(err_map!(Backend, "Error pinging session"))?;
                if count == 0 {
                    return Err(err_msg!(NotFound, "Session profile has been removed"));
                }
            }
            // Otherwise this activation's admission statement just read the profile row.
            Ok(())
        })
    }

    fn close(&mut self, commit: bool) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(self.close(commit))
    }
}

impl ExtDatabase for Postgres {
    fn admission<'a>(
        conn: &'a mut Connection<Self>,
        profile: ProfileRef<'a>,
        lock: Option<ProfileLock>,
    ) -> BoxFuture<'a, Result<Admitted, Error>> {
        Box::pin(async move {
            // One round trip: the head, read without a lock, beside the profile row. Only
            // the profile row is locked, and only inside a transaction: outside one a row
            // lock ends with the statement and protects nothing, but taking it would wait
            // for every transaction holding the row, which may be the very one this session
            // is serving from another connection.
            let base = match profile {
                ProfileRef::None => {
                    let head = Self::freshness_head(conn, false).await?;
                    return Ok(Admitted {
                        head,
                        profile: None,
                    });
                }
                ProfileRef::Name(_) => ADMIT_BY_NAME_QUERY,
                ProfileRef::Id(_) => ADMIT_BY_ID_QUERY,
            };
            let query = match lock {
                None => std::borrow::Cow::Borrowed(base),
                Some(ProfileLock::NoKeyUpdate) => format!("{base} FOR NO KEY UPDATE").into(),
                Some(ProfileLock::KeyShare) => format!("{base} FOR KEY SHARE").into(),
            };
            let query = sqlx::query(query.as_ref()).bind(super::freshness::HEAD_KEY);
            let query = match profile {
                ProfileRef::Name(name) => query.bind(name),
                ProfileRef::Id(id) => query.bind(id),
                ProfileRef::None => unreachable!(),
            };
            let Some(row) = query.fetch_optional(&mut *conn).await? else {
                // No such profile. The store is still checked before that is reported.
                let head = Self::freshness_head(conn, false).await?;
                return Ok(Admitted {
                    head,
                    profile: None,
                });
            };
            let head = row
                .try_get::<Option<String>, _>(0)?
                .map(|value| super::freshness::Head::decode(&value))
                .transpose()?;
            Ok(Admitted {
                head,
                profile: Some((row.try_get(1)?, row.try_get(2)?, row.try_get(3)?)),
            })
        })
    }

    fn freshness_head(
        conn: &mut Connection<Self>,
        lock: bool,
    ) -> BoxFuture<'_, Result<Option<super::freshness::Head>, Error>> {
        Box::pin(async move {
            // The locking read also makes the transaction's COMMIT synchronous, in the same
            // round trip: it is the first statement of a head advance.
            let query = if lock {
                "SELECT value, set_config('synchronous_commit', 'on', true) FROM config
                WHERE name = $1 FOR UPDATE"
            } else {
                CONFIG_FETCH_QUERY
            };
            let row = sqlx::query(query)
                .bind(super::freshness::HEAD_KEY)
                .fetch_optional(conn)
                .await?;
            row.map(|row| super::freshness::Head::decode(row.try_get::<&str, _>(0)?))
                .transpose()
        })
    }
    fn freshness_advance<'a>(
        conn: &'a mut Connection<Self>,
        head: &'a super::freshness::Head,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query(CONFIG_UPDATE_QUERY)
                .bind(super::freshness::HEAD_KEY)
                .bind(head.encode()?)
                .execute(conn)
                .await?;
            Ok(())
        })
    }
    fn freshness_write<'a>(
        conn: &'a mut Connection<Self>,
        head: &'a super::freshness::Head,
    ) -> BoxFuture<'a, Result<(), Error>> {
        Box::pin(async move {
            sqlx::query("SET LOCAL synchronous_commit = on")
                .execute(&mut *conn)
                .await?;
            sqlx::query(CONFIG_UPDATE_QUERY)
                .bind(super::freshness::HEAD_KEY)
                .bind(head.encode()?)
                .execute(conn)
                .await?;
            Ok(())
        })
    }

    fn reset_connection(conn: &mut Connection<Self>) -> BoxFuture<'_, bool> {
        Box::pin(async move {
            // A BEGIN interrupted before its acknowledgement can leave the
            // server inside a transaction that sqlx does not count. ROLLBACK
            // outside a transaction is only a warning.
            reset_depth::<Self>(conn).await
                && sqlx::Executor::execute(&mut *conn, "ROLLBACK")
                    .await
                    .is_ok()
        })
    }
}

impl QueryPrepare for PostgresBackend {
    type DB = Postgres;

    fn placeholder(index: i64) -> String {
        format!("${}", index)
    }

    fn limit_query<'q>(
        mut query: String,
        args: &mut QueryParams<'q, Self::DB>,
        offset: Option<i64>,
        limit: Option<i64>,
    ) -> String
    where
        i64: for<'e> sqlx::Encode<'e, Self::DB> + sqlx::Type<Self::DB>,
    {
        if offset.is_some() || limit.is_some() {
            let last_idx = (args.len() + 1) as i64;
            args.push(limit);
            args.push(offset.unwrap_or(0));
            let limit = replace_arg_placeholders::<Self>(" LIMIT $$ OFFSET $$", last_idx);
            query.push_str(&limit);
        }
        query
    }
}

/// The session's profile key. Only a session's first use needs the database for it; the
/// admission of each operation is the one `acquire_session` performs before its statement.
async fn acquire_key(
    session: &mut DbSession<Postgres>,
) -> Result<(ProfileId, Arc<ProfileKey>), Error> {
    if let Some(resolved) = session.profile_and_key() {
        return Ok(resolved);
    }
    acquire_session(session).await?;
    Ok(session.profile_and_key().unwrap())
}

async fn acquire_session(
    session: &'_ mut DbSession<Postgres>,
) -> Result<DbSessionActive<'_, Postgres>, Error> {
    session.make_active().await
}

#[allow(clippy::too_many_arguments)]
async fn perform_insert(
    active: &mut DbSessionTxn<'_, Postgres>,
    kind: EntryKind,
    enc_category: &[u8],
    enc_name: &[u8],
    enc_value: &[u8],
    enc_tags: Option<Vec<EncEntryTag>>,
    expiry_ms: Option<i64>,
    new_row: bool,
) -> Result<(), Error> {
    let row_id = if new_row {
        trace!("Insert entry");
        sqlx::query_scalar(INSERT_QUERY)
            .bind(active.profile_id)
            .bind(kind as i16)
            .bind(enc_category)
            .bind(enc_name)
            .bind(enc_value)
            .bind(expiry_ms.map(expiry_timestamp).transpose()?)
            .fetch_optional(active.connection_mut())
            .await?
            .ok_or_else(|| err_msg!(Duplicate, "Duplicate entry"))?
    } else {
        trace!("Update entry");
        let row_id: i64 = sqlx::query_scalar(UPDATE_QUERY)
            .bind(active.profile_id)
            .bind(kind as i16)
            .bind(enc_category)
            .bind(enc_name)
            .bind(enc_value)
            .bind(expiry_ms.map(expiry_timestamp).transpose()?)
            .fetch_one(active.connection_mut())
            .await
            .map_err(|_| err_msg!(NotFound, "Error updating existing entry"))?;
        sqlx::query(TAG_DELETE_QUERY)
            .bind(row_id)
            .execute(active.connection_mut())
            .await
            .map_err(err_map!(Backend, "Error removing existing entry tags"))?;
        row_id
    };
    if let Some(tags) = enc_tags {
        for tag in tags {
            sqlx::query(TAG_INSERT_QUERY)
                .bind(row_id)
                .bind(&tag.name)
                .bind(&tag.value)
                .bind(tag.plaintext as i16)
                .execute(active.connection_mut())
                .await
                .map_err(err_map!(Backend, "Error inserting entry tags"))?;
        }
    }
    Ok(())
}

async fn perform_remove(
    active: &mut DbSessionTxn<'_, Postgres>,
    kind: EntryKind,
    enc_category: &[u8],
    enc_name: &[u8],
    ignore_error: bool,
) -> Result<(), Error> {
    trace!("Remove entry");
    let done = sqlx::query(DELETE_QUERY)
        .bind(active.profile_id)
        .bind(kind as i16)
        .bind(enc_category)
        .bind(enc_name)
        .execute(active.connection_mut())
        .await
        .map_err(err_map!(Backend, "Error removing entry"))?;
    if done.rows_affected() == 0 && !ignore_error {
        Err(err_msg!(NotFound, "Entry not found"))
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn perform_scan(
    mut active: DbSessionRef<'_, Postgres>,
    profile_id: ProfileId,
    key: Arc<ProfileKey>,
    kind: Option<EntryKind>,
    category: Option<String>,
    tag_filter: Option<TagFilter>,
    offset: Option<i64>,
    limit: Option<i64>,
    order_by: Option<OrderBy>,
    descending: bool,
    for_update: bool,
) -> impl Stream<Item = Result<Vec<EncScanEntry>, Error>> + '_ {
    try_stream! {
        let mut params = QueryParams::new();
        params.push(profile_id);
        params.push(kind.map(|k| k as i16));
        let (enc_category, tag_filter) = unblock({
            let key = key.clone();
            let enc_category = category.map(|c| ProfileKey::prepare_input(c.as_bytes()));
            let params_len = params.len() + 1; // plus category
            move || {
                Result::<_, Error>::Ok((
                    enc_category
                        .map(|c| key.encrypt_entry_category(c))
                        .transpose()?,
                    encode_tag_filter::<PostgresBackend>(tag_filter, &key, params_len)?
                ))
            }
        }).await?;
        params.push(enc_category);
        let mut query = extend_query::<PostgresBackend>(SCAN_QUERY, &mut params, tag_filter, offset, limit, order_by, descending)?;
        if for_update {
            query.push_str(" FOR NO KEY UPDATE");
        }
        let mut batch = Vec::with_capacity(PAGE_SIZE);

        let mut acquired = acquire_session(&mut active).await?;
        let admitted = acquired.read_guard();
        let mut rows = sqlx::query_with(query.as_str(), params).fetch(acquired.connection_mut());
        while let Some(row) = rows.try_next().await? {
            let tags = row.try_get::<Option<String>, _>(5)?.map(String::into_bytes).unwrap_or_default();
            let kind: i16 = row.try_get(1)?;
            let kind = EntryKind::try_from(kind as usize)?;
            batch.push(EncScanEntry {
                kind, category: row.try_get(2)?, name: row.try_get(3)?, value: row.try_get(4)?, tags
            });
            if batch.len() == PAGE_SIZE {
                admitted.check().await?;
                yield batch.split_off(0);
            }
        }
        drop(rows);
        if active.is_owned() {
            active.close(false).await?;
        }
        drop(active);

        if !batch.is_empty() {
            admitted.check().await?;
            yield batch;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::db_utils::replace_arg_placeholders;

    #[test]
    fn postgres_simple_and_convert_args_works() {
        assert_eq!(
            &replace_arg_placeholders::<PostgresBackend>("This $$ is $10 a $$ string!", 3),
            "This $3 is $12 a $5 string!",
        );
    }
}
