//! Change journal and export: what a store holds, and what changed in it since a point.
//!
//! An application keeping an incremental backup takes one [`Export`] as its base, then reads
//! [`JournalChanges`] after the export's head. Restoring imports the base into an empty store
//! and applies the changes in order. The journal is turned on per store
//! ([`Backend::enable_journal`]); backends that do not keep one answer `Unsupported`.

use std::collections::HashSet;

use crate::{
    backend::{Backend, BackendSession},
    entry::{Entry, EntryKind, EntryOperation},
    error::{Error, ErrorKind},
};

/// How far a store's journal reaches: `journal_id` names the journal (a replaced or recreated
/// store has another), `seq` is the last change recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JournalHead {
    /// Identifier of this store's journal
    pub journal_id: uuid::Uuid,
    /// Sequence number of the last recorded change (0 before the first)
    pub seq: u64,
}

/// An entry with its absolute expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportEntry {
    /// The entry
    pub entry: Entry,
    /// When the entry expires, in Unix milliseconds
    pub expires_at_ms: Option<i64>,
}

/// The entries of one profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportProfile {
    /// The profile name
    pub name: String,
    /// Every unexpired entry of the profile, keys included
    pub entries: Vec<ExportEntry>,
}

/// Everything a store holds, read at one point.
#[derive(Clone, Debug)]
pub struct Export {
    /// The journal at the point of the export, if the store keeps one
    pub head: Option<JournalHead>,
    /// The default profile
    pub default_profile: String,
    /// Every profile
    pub profiles: Vec<ExportProfile>,
}

/// One item's change: its current content, or its removal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalChange {
    /// The item now holds this entry
    Upsert {
        /// Profile name
        profile: String,
        /// Current entry
        entry: ExportEntry,
    },
    /// The item is gone
    Delete {
        /// Profile name
        profile: String,
        /// Entry kind
        kind: EntryKind,
        /// Entry category
        category: String,
        /// Entry name
        name: String,
    },
}

/// The changes after a sequence number, at most one per item.
#[derive(Clone, Debug)]
pub struct JournalChanges {
    /// Changed items, each once, in the order of their last change
    pub changes: Vec<JournalChange>,
    /// The last sequence number these changes cover; read the next page after it
    pub through: u64,
    /// Whether changes after `through` are already recorded
    pub more: bool,
    /// Changes after the requested point are no longer in the journal (pruned, or the journal
    /// belongs to another store): take a new export instead
    pub rebase_needed: bool,
    /// The store's profiles at the time of the read; a profile missing here was removed
    pub profiles: Vec<String>,
}

const IMPORT_BATCH: usize = 500;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Milliseconds left until `expires_at_ms`, `Err(())` when already past.
fn remaining_ms(expires_at_ms: Option<i64>) -> Result<Option<i64>, ()> {
    match expires_at_ms {
        None => Ok(None),
        Some(at) => {
            let left = at - now_ms();
            if left > 0 {
                Ok(Some(left))
            } else {
                Err(())
            }
        }
    }
}

async fn session_commit<S: BackendSession>(mut session: S) -> Result<(), Error> {
    session.close(true).await
}

async fn ensure_profile<B: Backend>(backend: &B, name: &str) -> Result<(), Error> {
    if !backend.list_profiles().await?.iter().any(|p| p == name) {
        backend.create_profile(Some(name.to_owned())).await?;
    }
    Ok(())
}

async fn upsert<S: BackendSession>(session: &mut S, item: &ExportEntry) -> Result<(), Error> {
    let Ok(expiry) = remaining_ms(item.expires_at_ms) else {
        return Ok(());
    };
    let entry = &item.entry;
    let exists = session
        .fetch(entry.kind, &entry.category, &entry.name, false)
        .await?
        .is_some();
    let op = if exists {
        EntryOperation::Replace
    } else {
        EntryOperation::Insert
    };
    session
        .update(
            entry.kind,
            op,
            &entry.category,
            &entry.name,
            Some(entry.value.as_ref()),
            Some(entry.tags.as_ref()),
            expiry,
        )
        .await
}

/// Write an export into a store, creating its profiles. Entries already expired are skipped.
/// The target is expected to be empty; an existing entry is replaced.
pub async fn import<B: Backend>(backend: &B, export: &Export) -> Result<(), Error> {
    for profile in &export.profiles {
        ensure_profile(backend, &profile.name).await?;
        for batch in profile.entries.chunks(IMPORT_BATCH) {
            let mut session = backend.session(Some(profile.name.clone()), true)?;
            for item in batch {
                upsert(&mut session, item).await?;
            }
            session_commit(session).await?;
        }
    }
    if export
        .profiles
        .iter()
        .any(|p| p.name == export.default_profile)
    {
        backend
            .set_default_profile(export.default_profile.clone())
            .await?;
    }
    Ok(())
}

/// Apply journal changes, in order, to a store restored from an earlier export: upserts are
/// written, deletions removed, and profiles the source no longer has are removed. Changes
/// that ask for a rebase are refused: they carry nothing to apply.
pub async fn apply_changes<B: Backend>(backend: &B, changes: &JournalChanges) -> Result<(), Error> {
    if changes.rebase_needed {
        return Err(err_msg!(
            Input,
            "These changes do not continue the store: take a new export"
        ));
    }
    let mut created = HashSet::new();
    let mut open: Option<(String, B::Session)> = None;
    for change in &changes.changes {
        let profile = match change {
            JournalChange::Upsert { profile, .. } | JournalChange::Delete { profile, .. } => {
                profile
            }
        };
        // Consecutive changes to one profile share a transaction.
        if open.as_ref().map(|(p, _)| p != profile).unwrap_or(true) {
            if let Some((_, session)) = open.take() {
                session_commit(session).await?;
            }
            if created.insert(profile.clone()) {
                ensure_profile(backend, profile).await?;
            }
            open = Some((
                profile.clone(),
                backend.session(Some(profile.clone()), true)?,
            ));
        }
        let (_, session) = open.as_mut().expect("a session is open");
        match change {
            JournalChange::Upsert { entry, .. } => upsert(session, entry).await?,
            JournalChange::Delete {
                kind,
                category,
                name,
                ..
            } => match session
                .update(
                    *kind,
                    EntryOperation::Remove,
                    category,
                    name,
                    None,
                    None,
                    None,
                )
                .await
            {
                Ok(()) => (),
                Err(e) if e.kind() == ErrorKind::NotFound => (),
                Err(e) => return Err(e),
            },
        }
    }
    if let Some((_, session)) = open.take() {
        session_commit(session).await?;
    }
    let keep: HashSet<&String> = changes.profiles.iter().collect();
    for profile in backend.list_profiles().await? {
        if !keep.contains(&profile) {
            backend.remove_profile(profile).await?;
        }
    }
    Ok(())
}
