use std::collections::BTreeMap;
use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use async_stream::try_stream;
use futures_lite::{
    pin,
    stream::{Stream, StreamExt},
};

use sqlx::{
    sqlite::{Sqlite, SqlitePool},
    Acquire, Database, Error as SqlxError, Row, TransactionManager,
};

use super::{
    commit::Committer,
    db_utils::{
        decode_tags, decrypt_scan_batch, encode_profile_key, encode_tag_filter, expiry_timestamp,
        extend_query, prepare_tags, random_profile_name, Admitted, Connection, DbSession,
        DbSessionActive, DbSessionRef, DbSessionTxn, EncScanEntry, ExtDatabase, ProfileLock,
        ProfileRef,
        QueryParams, QueryPrepare, WriteGate, PAGE_SIZE,
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
pub use provision::SqliteStoreOptions;

const CONFIG_FETCH_QUERY: &str = "SELECT value FROM config WHERE name = ?1";
const CONFIG_UPDATE_QUERY: &str = "INSERT OR REPLACE INTO config (name, value) VALUES (?1, ?2)";
const COUNT_QUERY: &str = "SELECT COUNT(*) FROM items i
    WHERE profile_id = ?1
    AND (kind = ?2 OR ?2 IS NULL)
    AND (category = ?3 OR ?3 IS NULL)
    AND (expiry IS NULL OR DATETIME(expiry) > DATETIME('now'))";
const DELETE_QUERY: &str = "DELETE FROM items
    WHERE profile_id = ?1 AND kind = ?2 AND category = ?3 AND name = ?4";
const FETCH_QUERY: &str = "SELECT i.id, i.value,
    (SELECT GROUP_CONCAT(it.plaintext || ':' || HEX(it.name) || ':' || HEX(it.value))
        FROM items_tags it WHERE it.item_id = i.id) AS tags
    FROM items i WHERE i.profile_id = ?1 AND i.kind = ?2
    AND i.category = ?3 AND i.name = ?4
    AND (i.expiry IS NULL OR DATETIME(i.expiry) > DATETIME('now'))";
const INSERT_QUERY: &str =
    "INSERT OR IGNORE INTO items (profile_id, kind, category, name, value, expiry)
    VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
const UPDATE_QUERY: &str = "UPDATE items SET value=?5, expiry=?6 WHERE profile_id=?1 AND kind=?2
    AND category=?3 AND name=?4 RETURNING id";
const SCAN_QUERY: &str = "SELECT i.id, i.kind, i.category, i.name, i.value,
    (SELECT GROUP_CONCAT(it.plaintext || ':' || HEX(it.name) || ':' || HEX(it.value))
        FROM items_tags it WHERE it.item_id = i.id) AS tags
    FROM items i WHERE i.profile_id = ?1
    AND (i.kind = ?2 OR ?2 IS NULL)
    AND (i.category = ?3 OR ?3 IS NULL)
    AND (i.expiry IS NULL OR DATETIME(i.expiry) > DATETIME('now'))";
const DELETE_ALL_QUERY: &str = "DELETE FROM items AS i
    WHERE i.profile_id = ?1
    AND (i.kind = ?2 OR ?2 IS NULL)
    AND (i.category = ?3 OR ?3 IS NULL)";
const TAG_INSERT_QUERY: &str = "INSERT INTO items_tags
    (item_id, name, value, plaintext) VALUES (?1, ?2, ?3, ?4)";
const TAG_DELETE_QUERY: &str = "DELETE FROM items_tags
    WHERE item_id=?1";

/// A Sqlite database store
pub struct SqliteBackend {
    conn_pool: SqlitePool,
    active_profile: String,
    key_cache: Arc<KeyCache>,
    expected_freshness: Option<uuid::Uuid>,
    committer: Committer<Sqlite>,
    path: String,
    write_gate: WriteGate,
}

impl SqliteBackend {
    pub(crate) fn with_freshness_lineage(mut self, expected: Option<uuid::Uuid>) -> Self {
        self.expected_freshness = expected;
        self
    }

    async fn check_freshness(&self) -> Result<(), Error> {
        let mut conn = self.conn_pool.acquire().await?;
        let mut retry = super::freshness::ReadRetry::new(false);
        loop {
            let head = <Sqlite as ExtDatabase>::freshness_head(&mut conn, false).await?;
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
        let head = <Sqlite as ExtDatabase>::freshness_head(&mut conn, false).await?;
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
        <Sqlite as ExtDatabase>::start_transaction(&mut conn, false).await?;
        let result = async {
            if <Sqlite as ExtDatabase>::freshness_head(&mut conn, true)
                .await?
                .is_some()
            {
                return Err(err_msg!(Backend, "Store already bound"));
            }
            let head = super::freshness::Head::initial();
            witness.register(&head).await?;
            <Sqlite as ExtDatabase>::freshness_write(&mut conn, &head).await?;
            <Sqlite as sqlx::Database>::TransactionManager::commit(&mut conn).await?;
            Ok(head)
        }
        .await;
        if result.is_err() {
            <Sqlite as sqlx::Database>::TransactionManager::start_rollback(&mut conn);
        }
        result
    }

    pub(crate) fn new(
        conn_pool: SqlitePool,
        active_profile: String,
        key_cache: KeyCache,
        path: String,
        busy_timeout: std::time::Duration,
    ) -> Self {
        Self {
            conn_pool,
            active_profile,
            key_cache: Arc::new(key_cache),
            expected_freshness: None,
            committer: Committer::default(),
            path,
            write_gate: WriteGate::new(busy_timeout),
        }
    }
}

impl Debug for SqliteBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteStore")
            .field("active_profile", &self.active_profile)
            .field("path", &self.path)
            .finish()
    }
}

impl QueryPrepare for SqliteBackend {
    type DB = Sqlite;
}

impl Backend for SqliteBackend {
    type Session = DbSession<Sqlite>;

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
            let done =
                sqlx::query("INSERT OR IGNORE INTO profiles (name, profile_key) VALUES (?1, ?2)")
                    .bind(&name)
                    .bind(enc_key)
                    .execute(conn)
                    .await?;
            if done.rows_affected() == 0 {
                tx.close(false).await?;
                return Err(err_msg!(Duplicate, "Duplicate profile name"));
            }
            tx.freshness_dirty = true;
            tx.close(true).await?;
            self.key_cache
                .add_profile(
                    name.clone(),
                    done.last_insert_rowid(),
                    Arc::new(profile_key),
                )
                .await;
            Ok(name)
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
            conn.return_to_pool().await;
            let names = rows.into_iter().flat_map(|r| r.try_get(0)).collect();
            self.check_freshness().await?;
            Ok(names)
        })
    }

    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>> {
        Box::pin(async move {
            let mut tx = self.session(None, true)?;
            let conn = tx.metadata_connection().await?;
            let ret = sqlx::query("DELETE FROM profiles WHERE name=?")
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
                if sqlx::query("UPDATE profiles SET profile_key=?1 WHERE id=?2")
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
            if sqlx::query("UPDATE config SET value=?1 WHERE name='key'")
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
        .with_committer(self.committer.clone())
        .with_write_gate(self.write_gate.clone()))
    }

    fn close(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.conn_pool.close().await;
            Ok(())
        })
    }
}

impl BackendSession for DbSession<Sqlite> {
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
                                encode_tag_filter::<SqliteBackend>(tag_filter, &key, params_len)?,
                            ))
                        }
                    })
                    .await?;
                    params.push(enc_category);
                    let query = extend_query::<SqliteBackend>(
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
        _for_update: bool,
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
                    if let Some(row) = sqlx::query(FETCH_QUERY)
                        .bind(profile_id)
                        .bind(kind as i16)
                        .bind(enc_category)
                        .bind(enc_name)
                        .fetch_optional(active.connection_mut())
                        .await
                        .map_err(err_map!(Backend, "Error performing fetch query"))?
                    {
                        let value = row.try_get(1)?;
                        let tags = row.try_get(2)?;
                        let (category, name, value, tags) = unblock(move || {
                            let value =
                                key.decrypt_entry_value(category.as_ref(), name.as_ref(), value)?;
                            let enc_tags = decode_tags(tags)
                                .map_err(|_| err_msg!(Unexpected, "Error decoding entry tags"))?;
                            let tags = key.decrypt_entry_tags(enc_tags)?;
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
        _for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>, Error>> {
        let category = category.map(|c| c.to_string());
        Box::pin(async move {
            let mut retry = super::freshness::ReadRetry::new(self.in_transaction());
            loop {
                let result = async {
                    let category = category.clone();
                    let tag_filter = tag_filter.clone();
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
                        encode_tag_filter::<SqliteBackend>(tag_filter, &key, params_len)?,
                    ))
                }
            })
            .await?;
            params.push(enc_category);
            let query = extend_query::<SqliteBackend>(
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
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM profiles WHERE id=$1")
                .bind(sess.profile_id)
                .fetch_one(sess.connection_mut())
                .await
                .map_err(err_map!(Backend, "Error pinging session"))?;
            if count == 0 {
                Err(err_msg!(NotFound, "Session profile has been removed"))
            } else {
                Ok(())
            }
        })
    }

    fn close(&mut self, commit: bool) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(self.close(commit))
    }
}

impl ExtDatabase for Sqlite {
    fn admission<'a>(
        conn: &'a mut Connection<Self>,
        profile: ProfileRef<'a>,
        _lock: Option<ProfileLock>,
    ) -> BoxFuture<'a, Result<Admitted, Error>> {
        Box::pin(async move {
            let head = Self::freshness_head(&mut *conn, false).await?;
            let profile = match profile {
                ProfileRef::None => None,
                ProfileRef::Name(name) => {
                    sqlx::query_as("SELECT id, name, profile_key FROM profiles WHERE name=?1")
                        .bind(name)
                        .fetch_optional(&mut *conn)
                        .await
                        .map_err(err_map!(Backend, "Error fetching profile key"))?
                }
                ProfileRef::Id(id) => {
                    sqlx::query_as("SELECT id, name, profile_key FROM profiles WHERE id=?1")
                        .bind(id)
                        .fetch_optional(&mut *conn)
                        .await
                        .map_err(err_map!(Backend, "Error fetching profile key"))?
                }
            };
            Ok(Admitted { head, profile })
        })
    }

    fn freshness_head(
        conn: &mut Connection<Self>,
        lock: bool,
    ) -> BoxFuture<'_, Result<Option<super::freshness::Head>, Error>> {
        Box::pin(async move {
            let query = if lock {
                CONFIG_FETCH_QUERY
            } else {
                CONFIG_FETCH_QUERY
            };
            let value: Option<(String,)> = sqlx::query_as(query)
                .bind(super::freshness::HEAD_KEY)
                .fetch_optional(&mut *conn)
                .await?;
            let head = value
                .map(|v| super::freshness::Head::decode(&v.0))
                .transpose()?;
            if head.is_some() {
                let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
                    .fetch_one(&mut *conn)
                    .await?;
                let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
                    .fetch_one(&mut *conn)
                    .await?;
                if synchronous < 2 || matches!(journal.as_str(), "memory" | "off") {
                    return Err(err_msg!(
                        Backend,
                        "Bound store requires durable SQLite settings"
                    ));
                }
            }
            Ok(head)
        })
    }
    fn freshness_write<'a>(
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

    fn start_transaction(
        conn: &mut Connection<Self>,
        nested: bool,
    ) -> BoxFuture<'_, std::result::Result<(), SqlxError>> {
        // SQLx 0.8 supports a custom BEGIN statement. Reserve the writer in
        // that single operation: BEGIN followed by a no-op DELETE can fail
        // after SQLx has already incremented transaction depth, contaminating
        // the pooled connection and making later commits mere SAVEPOINT releases.
        <Sqlite as Database>::TransactionManager::begin(
            conn,
            if nested {
                None
            } else {
                Some(std::borrow::Cow::Borrowed("BEGIN IMMEDIATE"))
            },
        )
    }
}

/// The session's profile key. Only a session's first use needs the database for it; the
/// admission of each operation is the one `acquire_session` performs before its statement.
async fn acquire_key(
    session: &mut DbSession<Sqlite>,
) -> Result<(ProfileId, Arc<ProfileKey>), Error> {
    if let Some(resolved) = session.profile_and_key() {
        return Ok(resolved);
    }
    acquire_session(session).await?;
    Ok(session.profile_and_key().unwrap())
}

async fn acquire_session(
    session: &mut DbSession<Sqlite>,
) -> Result<DbSessionActive<'_, Sqlite>, Error> {
    session.make_active().await
}

#[allow(clippy::too_many_arguments)]
async fn perform_insert(
    active: &mut DbSessionTxn<'_, Sqlite>,
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
        let done = sqlx::query(INSERT_QUERY)
            .bind(active.profile_id)
            .bind(kind as i16)
            .bind(enc_category)
            .bind(enc_name)
            .bind(enc_value)
            .bind(expiry_ms.map(expiry_timestamp).transpose()?)
            .execute(active.connection_mut())
            .await
            .map_err(err_map!(Backend, "Error inserting new entry"))?;
        if done.rows_affected() == 0 {
            return Err(err_msg!(Duplicate, "Duplicate entry"));
        }
        done.last_insert_rowid()
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
    active: &mut DbSessionTxn<'_, Sqlite>,
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
    mut active: DbSessionRef<'_, Sqlite>,
    profile_id: ProfileId,
    key: Arc<ProfileKey>,
    kind: Option<EntryKind>,
    category: Option<String>,
    tag_filter: Option<TagFilter>,
    offset: Option<i64>,
    limit: Option<i64>,
    order_by: Option<OrderBy>,
    descending: bool,
) -> impl Stream<Item = Result<Vec<EncScanEntry>, Error>> + '_ {
    try_stream! {
        let mut params = QueryParams::new();
        params.push(profile_id);
        params.push(kind.map(|k| k as i16));
        let (enc_category, tag_filter) = unblock({
            let key = key.clone();
            let enc_category = category.as_ref().map(|c| ProfileKey::prepare_input(c.as_bytes()));
            let params_len = params.len() + 1; // plus category
            move || {
                Result::<_, Error>::Ok((
                    enc_category.map(|c| key.encrypt_entry_category(c)).transpose()?,
                    encode_tag_filter::<SqliteBackend>(tag_filter, &key, params_len)?
                ))
            }
        }).await?;
        params.push(enc_category);
        let query = extend_query::<SqliteBackend>(SCAN_QUERY, &mut params, tag_filter, offset, limit, order_by, descending)?;

        let mut batch = Vec::with_capacity(PAGE_SIZE);

        let mut acquired = acquire_session(&mut active).await?;
        let admitted = acquired.read_guard();
        let mut rows = sqlx::query_with(query.as_str(), params).fetch(acquired.connection_mut());
        while let Some(row) = rows.try_next().await? {
            let kind: u32 = row.try_get(1)?;
            let kind = EntryKind::try_from(kind as usize)?;
            batch.push(EncScanEntry {
                kind, category: row.try_get(2)?, name: row.try_get(3)?, value: row.try_get(4)?, tags: row.try_get(5)?
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
    use crate::future::block_on;
    use crate::protect::{generate_raw_store_key, StoreKeyMethod};

    #[tokio::test]
    async fn failed_writer_reservation_does_not_contaminate_pooled_transactions() {
        let dir = tempfile::tempdir().unwrap();
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("contention.db"))
            .create_if_missing(true)
            .busy_timeout(std::time::Duration::from_millis(10));
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(2)
            .connect_with(options.clone())
            .await
            .unwrap();
        sqlx::query("CREATE TABLE config (value INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE custody (value INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
        let mut owner = pool.acquire().await.unwrap();
        let mut contender = pool.acquire().await.unwrap();
        <Sqlite as ExtDatabase>::start_transaction(&mut owner, false)
            .await
            .unwrap();
        assert!(
            <Sqlite as ExtDatabase>::start_transaction(&mut contender, false)
                .await
                .is_err()
        );
        assert_eq!(
            <Sqlite as Database>::TransactionManager::get_transaction_depth(&contender),
            0,
            "failed admission must leave no hidden transaction on the pooled connection"
        );
        <Sqlite as Database>::TransactionManager::rollback(&mut owner)
            .await
            .unwrap();
        <Sqlite as ExtDatabase>::start_transaction(&mut contender, false)
            .await
            .unwrap();
        sqlx::query("INSERT INTO custody VALUES (1)")
            .execute(&mut *contender)
            .await
            .unwrap();
        <Sqlite as Database>::TransactionManager::commit(&mut contender)
            .await
            .unwrap();
        let mut independent = <sqlx::SqliteConnection as sqlx::Connection>::connect_with(&options)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM custody")
            .fetch_one(&mut independent)
            .await
            .unwrap();
        assert_eq!(count, 1, "reported commit must be durable outside the pool");
        <Sqlite as ExtDatabase>::start_transaction(&mut contender, false)
            .await
            .unwrap();
        sqlx::query("INSERT INTO custody VALUES (2)")
            .execute(&mut *contender)
            .await
            .unwrap();
        <Sqlite as Database>::TransactionManager::rollback(&mut contender)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM custody")
            .fetch_one(&mut independent)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    /// A writer queued behind the running one must not hold a connection the running one
    /// needs. With two connections, the queued writer used to wait out `busy_timeout` on the
    /// second one while the running writer waited for a connection to read with, so the
    /// running writer stalled until the queued one gave up ("database is locked"). Under load
    /// that held tenant transactions for 15s and failed the requests queued behind them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_queued_writer_holds_no_connection_the_running_writer_needs() {
        let dir = tempfile::tempdir().unwrap();
        let uri = format!(
            "sqlite://{}?max_connections=2&busy_timeout=1000",
            dir.path().join("gate.db").display()
        );
        let key = generate_raw_store_key(None).unwrap();
        let db = Arc::new(
            SqliteStoreOptions::new(uri.as_str())
                .unwrap()
                .provision(StoreKeyMethod::RawKey, key.as_ref(), None, true)
                .await
                .unwrap(),
        );
        // The running writer holds the write lock and one of the two connections.
        let mut writer = db.session(None, true).unwrap();
        writer
            .update(
                EntryKind::Item,
                EntryOperation::Insert,
                "c",
                "a",
                Some(b"1"),
                None,
                None,
            )
            .await
            .unwrap();
        let queued = tokio::spawn({
            let db = db.clone();
            async move {
                let mut session = db.session(None, true)?;
                session
                    .update(
                        EntryKind::Item,
                        EntryOperation::Insert,
                        "c",
                        "b",
                        Some(b"2"),
                        None,
                        None,
                    )
                    .await?;
                session.close(true).await
            }
        });
        // Until the second writer is queued: on the gate, or on the other connection.
        while db.write_gate.waiting() == 0
            && !(db.conn_pool.size() == 2 && db.conn_pool.num_idle() == 0)
        {
            tokio::task::yield_now().await;
        }
        // The running writer reads through another session before it commits.
        let mut reader = db.session(None, false).unwrap();
        let committed = reader
            .fetch(EntryKind::Item, "c", "a", false)
            .await
            .unwrap();
        assert!(committed.is_none(), "not committed yet");
        drop(reader);
        writer.close(true).await.unwrap();
        queued
            .await
            .unwrap()
            .expect("the queued writer is admitted once the running one commits");
    }

    #[test]
    fn sqlite_check_expiry_timestamp() {
        block_on(async {
            let key = generate_raw_store_key(None)?;
            let db = SqliteStoreOptions::in_memory()
                .provision(StoreKeyMethod::RawKey, key, None, false)
                .await?;
            let ts = expiry_timestamp(1000).unwrap();
            let check = sqlx::query("SELECT datetime('now'), ?1, datetime(?1) > datetime('now')")
                .bind(ts)
                .fetch_one(&db.conn_pool)
                .await?;
            let now: String = check.try_get(0)?;
            let cmp_ts: String = check.try_get(1)?;
            let cmp: bool = check.try_get(2)?;
            if !cmp {
                panic!("now ({}) > expiry timestamp ({})", now, cmp_ts);
            }
            Result::<_, Error>::Ok(())
        })
        .unwrap();
    }

    #[test]
    fn sqlite_check_expiry_timestamp_expired() {
        block_on(async {
            let key = generate_raw_store_key(None)?;
            let db = SqliteStoreOptions::in_memory()
                .provision(StoreKeyMethod::RawKey, key, None, false)
                .await?;
            let ts = expiry_timestamp(-1000).unwrap(); // put it to be already expired
            let check = sqlx::query("SELECT datetime('now'), ?1, datetime(?1) > datetime('now')")
                .bind(ts)
                .fetch_one(&db.conn_pool)
                .await?;
            let now: String = check.try_get(0)?;
            let cmp_ts: String = check.try_get(1)?;
            let cmp: bool = check.try_get(2)?;
            if cmp {
                panic!("now ({}) < expiry timestamp ({})", now, cmp_ts);
            }
            Result::<_, Error>::Ok(())
        })
        .unwrap();
    }

    #[test]
    fn sqlite_query_placeholders() {
        assert_eq!(
            &replace_arg_placeholders::<SqliteBackend>("This $$ is $10 a $$ string!", 3),
            "This ?3 is ?12 a ?5 string!",
        );
        assert_eq!(
            &replace_arg_placeholders::<SqliteBackend>("This $a is a string!", 1),
            "This $a is a string!",
        );
    }
}
