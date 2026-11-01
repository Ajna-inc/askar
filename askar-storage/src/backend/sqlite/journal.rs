//! The SQLite change journal and export.
//!
//! The journal is a table plus three triggers on `items`, so every write path records itself
//! in the same transaction: insert, replace (which also rewrites the tags), remove,
//! remove-all, and a profile removal cascading to its items. It holds the same encrypted
//! category and name as `items`, so a journal row finds its item by equality and reveals
//! nothing `items` does not. The store version is unchanged: a build that does not know the
//! journal opens the store, and its writes are still recorded by the triggers.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use sqlx::{sqlite::SqliteRow, Row, SqliteConnection};

use super::SqliteBackend;
use crate::{
    backend::{
        db_utils::{decrypt_scan_entry, EncScanEntry, Expiry},
        journal::{Export, ExportEntry, ExportProfile, JournalChange, JournalChanges, JournalHead},
    },
    entry::EntryKind,
    error::Error,
    protect::{EntryEncryptor, ProfileId, ProfileKey},
};

const JOURNAL_ID_KEY: &str = "journal_id";

const ENABLE: [&str; 4] = [
    "CREATE TABLE IF NOT EXISTS items_journal (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        profile_id INTEGER NOT NULL,
        kind INTEGER NOT NULL,
        category BLOB NOT NULL,
        name BLOB NOT NULL,
        op INTEGER NOT NULL
    )",
    "CREATE TRIGGER IF NOT EXISTS items_journal_ins AFTER INSERT ON items BEGIN
        INSERT INTO items_journal (profile_id, kind, category, name, op)
        VALUES (NEW.profile_id, NEW.kind, NEW.category, NEW.name, 1);
    END",
    "CREATE TRIGGER IF NOT EXISTS items_journal_upd AFTER UPDATE ON items BEGIN
        INSERT INTO items_journal (profile_id, kind, category, name, op)
        VALUES (NEW.profile_id, NEW.kind, NEW.category, NEW.name, 1);
    END",
    "CREATE TRIGGER IF NOT EXISTS items_journal_del AFTER DELETE ON items BEGIN
        INSERT INTO items_journal (profile_id, kind, category, name, op)
        VALUES (OLD.profile_id, OLD.kind, OLD.category, OLD.name, 2);
    END",
];

const ITEM_COLUMNS: &str = "i.kind, i.category, i.name, i.value, i.expiry,
    (SELECT GROUP_CONCAT(it.plaintext || ':' || HEX(it.name) || ':' || HEX(it.value))
        FROM items_tags it WHERE it.item_id = i.id) AS tags";

const UNEXPIRED: &str = "(i.expiry IS NULL OR DATETIME(i.expiry) > DATETIME('now'))";

impl SqliteBackend {
    pub(super) async fn journal_enable(&self) -> Result<JournalHead, Error> {
        self.refuse_bound_mutation().await?;
        let mut tx = self.conn_pool.begin().await?;
        for statement in ENABLE {
            sqlx::query(statement).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT OR IGNORE INTO config (name, value) VALUES (?1, ?2)")
            .bind(JOURNAL_ID_KEY)
            .bind(uuid::Uuid::new_v4().to_string())
            .execute(&mut *tx)
            .await?;
        let head = read_head(&mut *tx).await?;
        tx.commit().await?;
        head.ok_or_else(|| err_msg!(Unexpected, "Journal not recorded"))
    }

    pub(super) async fn journal_head_read(&self) -> Result<Option<JournalHead>, Error> {
        self.check_freshness().await?;
        let mut tx = self.conn_pool.begin().await?;
        let head = read_head(&mut *tx).await?;
        tx.commit().await?;
        Ok(head)
    }

    pub(super) async fn journal_changes_read(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<JournalChanges, Error> {
        self.check_freshness().await?;
        let mut tx = self.conn_pool.begin().await?;
        let head = read_head(&mut *tx)
            .await?
            .ok_or_else(|| err_msg!(Unsupported, "The store keeps no journal"))?;
        let profiles = self.read_profiles(&mut *tx).await?;
        let profile_names = profiles.values().map(|(n, _)| n.clone()).collect();

        let oldest: Option<i64> = sqlx::query_scalar("SELECT MIN(seq) FROM items_journal")
            .fetch_one(&mut *tx)
            .await?;
        let oldest = oldest.map(|s| s as u64).unwrap_or(head.seq + 1);
        if after > head.seq || oldest > after + 1 {
            tx.commit().await?;
            return Ok(JournalChanges {
                changes: Vec::new(),
                through: after,
                more: false,
                rebase_needed: true,
                profiles: profile_names,
            });
        }

        let rows = sqlx::query(
            "SELECT seq, profile_id, kind, category, name FROM items_journal
            WHERE seq > ?1 ORDER BY seq LIMIT ?2",
        )
        .bind(after as i64)
        .bind(limit.max(1) as i64)
        .fetch_all(&mut *tx)
        .await?;
        let through = match rows.last() {
            Some(row) => row.try_get::<i64, _>(0)? as u64,
            None => after,
        };

        // One change per item, at the position of its last change.
        let mut keys: Vec<(ProfileId, i64, Vec<u8>, Vec<u8>)> = Vec::with_capacity(rows.len());
        for row in rows.iter() {
            keys.push((
                row.try_get(1)?,
                row.try_get(2)?,
                row.try_get(3)?,
                row.try_get(4)?,
            ));
        }
        let mut seen = HashSet::new();
        let mut last_first: Vec<_> = Vec::with_capacity(keys.len());
        for key in keys.into_iter().rev() {
            if seen.insert(key.clone()) {
                last_first.push(key);
            }
        }
        last_first.reverse();

        let mut changes = Vec::with_capacity(last_first.len());
        for (profile_id, kind, category, name) in last_first {
            // Rows of a removed profile: the profile list says it is gone.
            let Some((profile, key)) = profiles.get(&profile_id) else {
                continue;
            };
            let kind = EntryKind::try_from(kind as usize)?;
            let current = sqlx::query(&format!(
                "SELECT {ITEM_COLUMNS} FROM items i
                WHERE i.profile_id = ?1 AND i.kind = ?2 AND i.category = ?3 AND i.name = ?4
                AND {UNEXPIRED}"
            ))
            .bind(profile_id)
            .bind(kind as i16)
            .bind(&category)
            .bind(&name)
            .fetch_optional(&mut *tx)
            .await?;
            changes.push(match current {
                Some(row) => JournalChange::Upsert {
                    profile: profile.clone(),
                    entry: decode_item(&row, key)?,
                },
                None => JournalChange::Delete {
                    profile: profile.clone(),
                    kind,
                    category: key.decrypt_entry_category(category)?,
                    name: key.decrypt_entry_name(name)?,
                },
            });
        }
        tx.commit().await?;
        Ok(JournalChanges {
            changes,
            through,
            more: through < head.seq,
            rebase_needed: false,
            profiles: profile_names,
        })
    }

    pub(super) async fn journal_prune_rows(&self, through: u64) -> Result<u64, Error> {
        self.refuse_bound_mutation().await?;
        let mut tx = self.conn_pool.begin().await?;
        if read_head(&mut *tx).await?.is_none() {
            return Err(err_msg!(Unsupported, "The store keeps no journal"));
        }
        let done = sqlx::query("DELETE FROM items_journal WHERE seq <= ?1")
            .bind(through as i64)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(done)
    }

    pub(super) async fn export_all(&self) -> Result<Export, Error> {
        self.check_freshness().await?;
        // One read transaction: every profile and the journal head at the same point.
        let mut tx = self.conn_pool.begin().await?;
        let head = read_head(&mut *tx).await?;
        let default_profile: String =
            sqlx::query_scalar("SELECT value FROM config WHERE name = 'default_profile'")
                .fetch_one(&mut *tx)
                .await?;
        let profiles = self.read_profiles(&mut *tx).await?;
        let mut ids: Vec<_> = profiles.keys().copied().collect();
        ids.sort_unstable();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let (name, key) = &profiles[&id];
            let rows = sqlx::query(&format!(
                "SELECT {ITEM_COLUMNS} FROM items i
                WHERE i.profile_id = ?1 AND {UNEXPIRED} ORDER BY i.id"
            ))
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
            let mut entries = Vec::with_capacity(rows.len());
            for row in rows.iter() {
                entries.push(decode_item(row, key)?);
            }
            out.push(ExportProfile {
                name: name.clone(),
                entries,
            });
        }
        tx.commit().await?;
        Ok(Export {
            head,
            default_profile,
            profiles: out,
        })
    }

    async fn read_profiles(
        &self,
        conn: &mut SqliteConnection,
    ) -> Result<HashMap<ProfileId, (String, Arc<ProfileKey>)>, Error> {
        let rows = sqlx::query("SELECT id, name, profile_key FROM profiles")
            .fetch_all(&mut *conn)
            .await?;
        let mut profiles = HashMap::with_capacity(rows.len());
        for row in rows {
            let id: ProfileId = row.try_get(0)?;
            let name: String = row.try_get(1)?;
            let key = self.key_cache.load_key(row.try_get(2)?).await?;
            profiles.insert(id, (name, Arc::new(key)));
        }
        Ok(profiles)
    }
}

async fn read_head(conn: &mut SqliteConnection) -> Result<Option<JournalHead>, Error> {
    let id: Option<String> = sqlx::query_scalar("SELECT value FROM config WHERE name = ?1")
        .bind(JOURNAL_ID_KEY)
        .fetch_optional(&mut *conn)
        .await?;
    let Some(id) = id else { return Ok(None) };
    let journal_id =
        uuid::Uuid::parse_str(&id).map_err(|_| err_msg!(Unexpected, "Invalid journal id"))?;
    let seq: Option<i64> =
        sqlx::query_scalar("SELECT seq FROM sqlite_sequence WHERE name = 'items_journal'")
            .fetch_optional(&mut *conn)
            .await?;
    Ok(Some(JournalHead {
        journal_id,
        seq: seq.unwrap_or(0) as u64,
    }))
}

fn decode_item(row: &SqliteRow, key: &ProfileKey) -> Result<ExportEntry, Error> {
    let kind: i64 = row.try_get(0)?;
    let expiry: Option<Expiry> = row.try_get(4)?;
    let tags: Option<Vec<u8>> = row.try_get(5)?;
    let entry = decrypt_scan_entry(
        None,
        EncScanEntry {
            kind: EntryKind::try_from(kind as usize)?,
            category: row.try_get(1)?,
            name: row.try_get(2)?,
            value: row.try_get(3)?,
            tags: tags.unwrap_or_default(),
        },
        key,
    )?;
    Ok(ExportEntry {
        entry,
        expires_at_ms: expiry.map(|e| e.timestamp_millis()),
    })
}
