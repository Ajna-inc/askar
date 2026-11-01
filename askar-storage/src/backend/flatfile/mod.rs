//! Flat file-based storage backend - extremely lightweight alternative to SQLite/PostgreSQL
//!
//! This backend uses a simple directory structure and binary file format:
//! - No SQL overhead
//! - No database dependencies
//! - Minimal memory footprint
//! - Direct file I/O for maximum simplicity
//!
//! Structure:
//! ```text
//! store_dir/
//!   ├── .config          # Store metadata (profile list, default profile, etc.)
//!   ├── .store_key       # Encrypted store key
//!   └── profiles/
//!       ├── default/
//!       │   ├── .profile_key    # Encrypted profile key
//!       │   └── entries/
//!       │       ├── kms_<category>_<name>.bin
//!       │       └── item_<category>_<name>.bin
//!       └── profile2/
//!           └── ...
//! ```

use std::collections::HashMap;
use std::fmt::{self, Debug, Formatter};
use std::fs::{self, File};
use std::io::{Read, Write as IoWrite};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use async_stream::try_stream;

use super::{Backend, BackendSession};
use crate::{
    backend::OrderBy,
    crypto::buffer::SecretBytes,
    entry::{Entry, EntryKind, EntryOperation, EntryTag, Scan, TagFilter},
    error::Error,
    future::BoxFuture,
    protect::{EntryEncryptor, KeyCache, PassKey, ProfileKey, StoreKeyMethod},
    wql,
};

mod provision;
pub use provision::FlatFileStoreOptions;

// The flat-file engine has no atomic external commit integration. Never silently
// accept it in a deployment configured for independently witnessed freshness.
fn refuse_freshness_deployment() -> Result<(), Error> {
    if std::env::var_os("ASKAR_FRESHNESS_LINEAGE").is_some()
        || std::env::var_os("ASKAR_FRESHNESS_WITNESS_URL").is_some()
    {
        return Err(err_msg!(
            Unsupported,
            "Freshness-bound deployments do not support flat-file storage"
        ));
    }
    Ok(())
}

const CONFIG_FILE: &str = ".config";
const STORE_KEY_FILE: &str = ".store_key";
const PROFILE_KEY_FILE: &str = ".profile_key";
const PROFILES_DIR: &str = "profiles";
const ENTRIES_DIR: &str = "entries";
const PAGE_SIZE: usize = 100;

/// Helper function to check if tags match a WQL filter
fn matches_tag_filter(tags: &[EntryTag], query: &wql::Query) -> bool {
    use wql::Query;

    match query {
        Query::Eq(name, value) => tags.iter().any(|t| t.name() == name && t.value() == value),
        Query::Neq(name, value) => !tags.iter().any(|t| t.name() == name && t.value() == value),
        Query::And(queries) => queries.iter().all(|q| matches_tag_filter(tags, q)),
        Query::Or(queries) => queries.iter().any(|q| matches_tag_filter(tags, q)),
        Query::Not(q) => !matches_tag_filter(tags, q),
        Query::In(name, values) => tags
            .iter()
            .any(|t| t.name() == name && values.contains(&t.value().to_string())),
        Query::Exist(names) => names
            .iter()
            .all(|name| tags.iter().any(|t| t.name() == name)),
        _ => true, // For unsupported filters, allow all
    }
}

/// Configuration stored in the .config file
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoreConfig {
    default_profile: String,
    profiles: Vec<String>,
    version: u32,
}

/// Binary format for entry files
/// Format: [kind:1][category_len:2][category][name_len:2][name][value_len:4][value][tag_count:2][tags...]
/// Each tag: [encrypted:1][name_len:2][name][value_len:2][value]
#[derive(Debug, Clone)]
struct EntryFile {
    kind: EntryKind,
    category: Vec<u8>,
    name: Vec<u8>,
    value: Vec<u8>,
    tags: Vec<(bool, Vec<u8>, Vec<u8>)>, // (plaintext, name, value)
}

impl EntryFile {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();

        // kind (1 byte)
        buf.push(self.kind as u8);

        // category
        buf.extend_from_slice(&(self.category.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.category);

        // name
        buf.extend_from_slice(&(self.name.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.name);

        // value
        buf.extend_from_slice(&(self.value.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.value);

        // tags
        buf.extend_from_slice(&(self.tags.len() as u16).to_le_bytes());
        for (plaintext, tag_name, tag_value) in &self.tags {
            buf.push(*plaintext as u8);
            buf.extend_from_slice(&(tag_name.len() as u16).to_le_bytes());
            buf.extend_from_slice(tag_name);
            buf.extend_from_slice(&(tag_value.len() as u16).to_le_bytes());
            buf.extend_from_slice(tag_value);
        }

        Ok(buf)
    }

    fn decode(data: &[u8]) -> Result<Self, Error> {
        let mut pos = 0;

        if data.len() < 1 {
            return Err(err_msg!(Unexpected, "Invalid entry file: too short"));
        }

        let kind = match data[pos] {
            1 => EntryKind::Kms,
            2 => EntryKind::Item,
            _ => return Err(err_msg!(Unexpected, "Invalid entry kind")),
        };
        pos += 1;

        // Read category
        if pos + 2 > data.len() {
            return Err(err_msg!(
                Unexpected,
                "Invalid entry file: truncated category length"
            ));
        }
        let category_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + category_len > data.len() {
            return Err(err_msg!(
                Unexpected,
                "Invalid entry file: truncated category"
            ));
        }
        let category = data[pos..pos + category_len].to_vec();
        pos += category_len;

        // Read name
        if pos + 2 > data.len() {
            return Err(err_msg!(
                Unexpected,
                "Invalid entry file: truncated name length"
            ));
        }
        let name_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + name_len > data.len() {
            return Err(err_msg!(Unexpected, "Invalid entry file: truncated name"));
        }
        let name = data[pos..pos + name_len].to_vec();
        pos += name_len;

        // Read value
        if pos + 4 > data.len() {
            return Err(err_msg!(
                Unexpected,
                "Invalid entry file: truncated value length"
            ));
        }
        let value_len =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + value_len > data.len() {
            return Err(err_msg!(Unexpected, "Invalid entry file: truncated value"));
        }
        let value = data[pos..pos + value_len].to_vec();
        pos += value_len;

        // Read tags
        if pos + 2 > data.len() {
            return Err(err_msg!(
                Unexpected,
                "Invalid entry file: truncated tag count"
            ));
        }
        let tag_count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let mut tags = Vec::with_capacity(tag_count);
        for _ in 0..tag_count {
            if pos + 1 > data.len() {
                return Err(err_msg!(
                    Unexpected,
                    "Invalid entry file: truncated tag plaintext flag"
                ));
            }
            let plaintext = data[pos] != 0;
            pos += 1;

            if pos + 2 > data.len() {
                return Err(err_msg!(
                    Unexpected,
                    "Invalid entry file: truncated tag name length"
                ));
            }
            let tag_name_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + tag_name_len > data.len() {
                return Err(err_msg!(
                    Unexpected,
                    "Invalid entry file: truncated tag name"
                ));
            }
            let tag_name = data[pos..pos + tag_name_len].to_vec();
            pos += tag_name_len;

            if pos + 2 > data.len() {
                return Err(err_msg!(
                    Unexpected,
                    "Invalid entry file: truncated tag value length"
                ));
            }
            let tag_value_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + tag_value_len > data.len() {
                return Err(err_msg!(
                    Unexpected,
                    "Invalid entry file: truncated tag value"
                ));
            }
            let tag_value = data[pos..pos + tag_value_len].to_vec();
            pos += tag_value_len;

            tags.push((plaintext, tag_name, tag_value));
        }

        Ok(EntryFile {
            kind,
            category,
            name,
            value,
            tags,
        })
    }
}

/// In-memory index for fast lookups
#[derive(Debug, Clone)]
struct EntryIndex {
    path: PathBuf,
    kind: EntryKind,
    category: String,
    name: String,
}

/// A flat file-based database store
pub struct FlatFileBackend {
    store_path: PathBuf,
    active_profile: String,
    key_cache: Arc<KeyCache>,
    index: Arc<RwLock<HashMap<String, Vec<EntryIndex>>>>, // profile -> entries
}

impl FlatFileBackend {
    pub(crate) fn new(
        store_path: PathBuf,
        active_profile: String,
        key_cache: KeyCache,
    ) -> Result<Self, Error> {
        let backend = Self {
            store_path,
            active_profile,
            key_cache: Arc::new(key_cache),
            index: Arc::new(RwLock::new(HashMap::new())),
        };

        // Build initial index
        backend.rebuild_index()?;

        Ok(backend)
    }

    fn config_path(&self) -> PathBuf {
        self.store_path.join(CONFIG_FILE)
    }

    fn profile_dir(&self, profile: &str) -> PathBuf {
        self.store_path.join(PROFILES_DIR).join(profile)
    }

    fn entries_dir(&self, profile: &str) -> PathBuf {
        self.profile_dir(profile).join(ENTRIES_DIR)
    }

    fn read_config(&self) -> Result<StoreConfig, Error> {
        let config_path = self.config_path();
        if !config_path.exists() {
            return Err(err_msg!(NotFound, "Store config not found"));
        }

        let mut file = File::open(&config_path)
            .map_err(|e| err_msg!(Backend, "Failed to open config: {}", e))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| err_msg!(Backend, "Failed to read config: {}", e))?;

        serde_json::from_str(&contents)
            .map_err(|e| err_msg!(Backend, "Failed to parse config: {}", e))
    }

    fn write_config(&self, config: &StoreConfig) -> Result<(), Error> {
        let config_path = self.config_path();
        let contents = serde_json::to_string_pretty(config)
            .map_err(|e| err_msg!(Backend, "Failed to serialize config: {}", e))?;

        let mut file = File::create(&config_path)
            .map_err(|e| err_msg!(Backend, "Failed to create config: {}", e))?;

        file.write_all(contents.as_bytes())
            .map_err(|e| err_msg!(Backend, "Failed to write config: {}", e))?;

        Ok(())
    }

    fn rebuild_index(&self) -> Result<(), Error> {
        let mut index = self
            .index
            .write()
            .map_err(|_| err_msg!(Backend, "Failed to acquire write lock on index"))?;

        index.clear();

        let config = self.read_config()?;

        use crate::protect::EntryEncryptor;

        for profile in &config.profiles {
            // Only rebuild index for profiles that have keys loaded in cache
            let profile_key =
                match futures_lite::future::block_on(self.key_cache.get_profile(profile)) {
                    Some((_id, key)) => key,
                    None => {
                        // Profile key not in cache, skip this profile
                        // We'll load entries on-demand when this profile is accessed
                        continue;
                    }
                };

            let entries_dir = self.entries_dir(profile);
            if !entries_dir.exists() {
                // Profile directory doesn't exist yet, create empty entry list
                index.insert(profile.clone(), Vec::new());
                continue;
            }

            let entries = fs::read_dir(&entries_dir)
                .map_err(|e| err_msg!(Backend, "Failed to read entries directory: {}", e))?;

            let mut profile_entries = Vec::new();

            for entry in entries {
                let entry = entry.map_err(|e| err_msg!(Backend, "Failed to read entry: {}", e))?;
                let path = entry.path();

                if !path.is_file() || !path.extension().map_or(false, |e| e == "bin") {
                    continue;
                }

                // Read and parse entry to get metadata
                let mut file = File::open(&path)
                    .map_err(|e| err_msg!(Backend, "Failed to open entry file: {}", e))?;

                let mut data = Vec::new();
                file.read_to_end(&mut data)
                    .map_err(|e| err_msg!(Backend, "Failed to read entry file: {}", e))?;

                let entry_file = EntryFile::decode(&data)?;

                // Decrypt category and name for the index
                let category = profile_key.decrypt_entry_category(entry_file.category.clone())?;
                let name = profile_key.decrypt_entry_name(entry_file.name.clone())?;

                profile_entries.push(EntryIndex {
                    path,
                    kind: entry_file.kind,
                    category,
                    name,
                });
            }

            index.insert(profile.clone(), profile_entries);
        }

        Ok(())
    }

    fn entry_filename(kind: EntryKind, category: &str, name: &str) -> String {
        let kind_str = match kind {
            EntryKind::Kms => "kms",
            EntryKind::Item => "item",
        };

        // Use a simple hash to avoid filesystem issues with special characters
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        category.hash(&mut hasher);
        name.hash(&mut hasher);
        let hash = hasher.finish();

        format!("{}_{:016x}.bin", kind_str, hash)
    }
}

impl Debug for FlatFileBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("FlatFileBackend")
            .field("store_path", &self.store_path)
            .field("active_profile", &self.active_profile)
            .finish()
    }
}

impl Backend for FlatFileBackend {
    type Session = FlatFileSession;

    fn create_profile(&self, name: Option<String>) -> BoxFuture<'_, Result<String, Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            let profile_name = name.unwrap_or_else(|| {
                use rand::Rng;
                let mut rng = rand::thread_rng();
                format!("profile_{:08x}", rng.gen::<u32>())
            });

            let mut config = self.read_config()?;

            if config.profiles.contains(&profile_name) {
                return Err(err_msg!(Duplicate, "Profile already exists"));
            }

            // Create profile directory structure
            let profile_dir = self.profile_dir(&profile_name);
            fs::create_dir_all(&profile_dir)
                .map_err(|e| err_msg!(Backend, "Failed to create profile directory: {}", e))?;

            let entries_dir = self.entries_dir(&profile_name);
            fs::create_dir_all(&entries_dir)
                .map_err(|e| err_msg!(Backend, "Failed to create entries directory: {}", e))?;

            // Create profile key
            let profile_key = ProfileKey::new()?;
            let profile_id = config.profiles.len() as i64; // Simple counter
            let encoded_key = self
                .key_cache
                .store_key
                .wrap_data(profile_key.to_bytes()?)?;

            // Store encrypted profile key
            let profile_key_path = profile_dir.join(PROFILE_KEY_FILE);

            let mut file = File::create(&profile_key_path)
                .map_err(|e| err_msg!(Backend, "Failed to create profile key file: {}", e))?;
            file.write_all(&encoded_key)
                .map_err(|e| err_msg!(Backend, "Failed to write profile key: {}", e))?;

            // Update config
            config.profiles.push(profile_name.clone());
            self.write_config(&config)?;

            // Update index and key cache
            {
                let mut index = self
                    .index
                    .write()
                    .map_err(|_| err_msg!(Backend, "Failed to acquire write lock on index"))?;
                index.insert(profile_name.clone(), Vec::new());
            } // Drop lock before async call

            // Add to key cache
            self.key_cache
                .add_profile(profile_name.clone(), profile_id, Arc::new(profile_key))
                .await;

            Ok(profile_name)
        })
    }

    fn get_active_profile(&self) -> String {
        self.active_profile.clone()
    }

    fn get_default_profile(&self) -> BoxFuture<'_, Result<String, Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            let config = self.read_config()?;
            Ok(config.default_profile)
        })
    }

    fn set_default_profile(&self, profile: String) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            let mut config = self.read_config()?;

            if !config.profiles.contains(&profile) {
                return Err(err_msg!(NotFound, "Profile not found"));
            }

            config.default_profile = profile;
            self.write_config(&config)?;

            Ok(())
        })
    }

    fn list_profiles(&self) -> BoxFuture<'_, Result<Vec<String>, Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            let config = self.read_config()?;
            Ok(config.profiles)
        })
    }

    fn remove_profile(&self, name: String) -> BoxFuture<'_, Result<bool, Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            let mut config = self.read_config()?;

            if !config.profiles.contains(&name) {
                return Ok(false);
            }

            // Remove profile directory
            let profile_dir = self.profile_dir(&name);
            if profile_dir.exists() {
                fs::remove_dir_all(&profile_dir)
                    .map_err(|e| err_msg!(Backend, "Failed to remove profile directory: {}", e))?;
            }

            // Update config
            config.profiles.retain(|p| p != &name);
            if config.default_profile == name && !config.profiles.is_empty() {
                config.default_profile = config.profiles[0].clone();
            }
            self.write_config(&config)?;

            // Update index
            let mut index = self
                .index
                .write()
                .map_err(|_| err_msg!(Backend, "Failed to acquire write lock on index"))?;
            index.remove(&name);

            Ok(true)
        })
    }

    fn rename_profile(
        &self,
        from_name: String,
        to_name: String,
    ) -> BoxFuture<'_, Result<bool, Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            let mut config = self.read_config()?;

            if !config.profiles.contains(&from_name) {
                return Ok(false);
            }

            if config.profiles.contains(&to_name) {
                return Err(err_msg!(Duplicate, "Target profile already exists"));
            }

            // Rename directory
            let from_dir = self.profile_dir(&from_name);
            let to_dir = self.profile_dir(&to_name);

            fs::rename(&from_dir, &to_dir)
                .map_err(|e| err_msg!(Backend, "Failed to rename profile directory: {}", e))?;

            // Update config
            config.profiles.retain(|p| p != &from_name);
            config.profiles.push(to_name.clone());
            if config.default_profile == from_name {
                config.default_profile = to_name.clone();
            }
            self.write_config(&config)?;

            // Update index
            let mut index = self
                .index
                .write()
                .map_err(|_| err_msg!(Backend, "Failed to acquire write lock on index"))?;
            if let Some(entries) = index.remove(&from_name) {
                index.insert(to_name, entries);
            }

            Ok(true)
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
        _order_by: Option<OrderBy>,
        _descending: bool,
    ) -> BoxFuture<'_, Result<Scan<'static, Entry>, Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            let profile = profile.unwrap_or_else(|| self.active_profile.clone());
            let (_profile_id, profile_key) = self
                .key_cache
                .get_profile(&profile)
                .await
                .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;

            let index = self
                .index
                .read()
                .map_err(|_| err_msg!(Backend, "Failed to acquire read lock on index"))?;

            let entries = index
                .get(&profile)
                .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?
                .clone();

            drop(index); // Release lock

            let stream = try_stream! {
                let mut results = Vec::new();
                let mut count = 0;
                let offset = offset.unwrap_or(0) as usize;
                let limit = limit.map(|l| l as usize);

                for (idx, entry_idx) in entries.iter().enumerate() {
                    // Apply filters
                    if let Some(k) = kind {
                        if entry_idx.kind != k {
                            continue;
                        }
                    }

                    if let Some(ref cat) = category {
                        if &entry_idx.category != cat {
                            continue;
                        }
                    }

                    // Skip offset
                    if idx < offset {
                        continue;
                    }

                    // Read entry from file
                    let mut file = File::open(&entry_idx.path)
                        .map_err(|e| Error::from(err_msg!(Backend, "Failed to open entry file: {}", e)))?;

                    let mut data = Vec::new();
                    file.read_to_end(&mut data)
                        .map_err(|e| Error::from(err_msg!(Backend, "Failed to read entry file: {}", e)))?;

                    let entry_file = EntryFile::decode(&data)?;

                    // Decrypt entry (category, name, value)
                    let decrypted_category = profile_key.decrypt_entry_category(entry_file.category.clone())?;
                    let decrypted_name = profile_key.decrypt_entry_name(entry_file.name.clone())?;

                    let decrypted_value = profile_key.decrypt_entry_value(&entry_file.category, &entry_file.name, entry_file.value.clone())?;

                    let mut tags = Vec::new();
                    for (plaintext, tag_name, tag_value) in &entry_file.tags {
                        let tag = if *plaintext {
                            EntryTag::Plaintext(
                                String::from_utf8_lossy(tag_name).to_string(),
                                String::from_utf8_lossy(tag_value).to_string(),
                            )
                        } else {
                            let dec_name_bytes = profile_key.decrypt_tag_name(tag_name.clone())?;
                            let dec_name = String::from_utf8_lossy(&dec_name_bytes.into_vec()).to_string();
                            let dec_value_bytes = profile_key.decrypt_tag_value(tag_value.clone())?;
                            let dec_value = String::from_utf8_lossy(&dec_value_bytes.into_vec()).to_string();
                            EntryTag::Encrypted(dec_name, dec_value)
                        };
                        tags.push(tag);
                    }

                    // Apply tag filter
                    if let Some(ref filter) = tag_filter {
                        if !matches_tag_filter(&tags, &filter.query) {
                            continue;
                        }
                    }

                    let entry = Entry::new(
                        entry_file.kind,
                        decrypted_category,
                        decrypted_name,
                        decrypted_value,
                        tags,
                    );

                    results.push(entry);
                    count += 1;

                    if let Some(lim) = limit {
                        if count >= lim {
                            break;
                        }
                    }

                    if results.len() >= PAGE_SIZE {
                        yield results;
                        results = Vec::new();
                    }
                }

                if !results.is_empty() {
                    yield results;
                }
            };

            Ok(Scan::new(stream, PAGE_SIZE))
        })
    }

    fn session(&self, profile: Option<String>, transaction: bool) -> Result<Self::Session, Error> {
        refuse_freshness_deployment()?;
        let profile = profile.unwrap_or_else(|| self.active_profile.clone());

        Ok(FlatFileSession {
            backend: self.clone_ref(),
            profile,
            transaction,
            pending_ops: Vec::new(),
        })
    }

    fn rekey(
        &mut self,
        _method: StoreKeyMethod,
        _key: PassKey<'_>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            // Re-encrypt all profile keys with new store key
            let _config = self.read_config()?;

            // This is complex - for now, return error
            Err(err_msg!(
                Unsupported,
                "Rekey not yet implemented for flat file backend"
            ))
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            Ok(())
        })
    }
}

impl FlatFileBackend {
    fn clone_ref(&self) -> Arc<Self> {
        // This is a workaround - we need to restructure to use Arc internally
        Arc::new(Self {
            store_path: self.store_path.clone(),
            active_profile: self.active_profile.clone(),
            key_cache: Arc::clone(&self.key_cache),
            index: Arc::clone(&self.index),
        })
    }
}

/// A session for querying the flat file store
pub struct FlatFileSession {
    backend: Arc<FlatFileBackend>,
    profile: String,
    transaction: bool,
    pending_ops: Vec<Box<dyn FnOnce() -> Result<(), Error> + Send>>,
}

impl std::fmt::Debug for FlatFileSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlatFileSession")
            .field("profile", &self.profile)
            .field("transaction", &self.transaction)
            .finish()
    }
}

impl BackendSession for FlatFileSession {
    fn count<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            // Get profile key if we need tag filtering
            let profile_key = if tag_filter.is_some() {
                let (_, key) = self
                    .backend
                    .key_cache
                    .get_profile(&self.profile)
                    .await
                    .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;
                Some(key)
            } else {
                None
            };

            let index = self
                .backend
                .index
                .read()
                .map_err(|_| err_msg!(Backend, "Failed to acquire read lock on index"))?;

            let entries = index
                .get(&self.profile)
                .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;

            let mut count = 0;

            for entry_idx in entries {
                if let Some(k) = kind {
                    if entry_idx.kind != k {
                        continue;
                    }
                }

                if let Some(cat) = category {
                    if entry_idx.category != cat {
                        continue;
                    }
                }

                // If tag filter is present, read and decrypt the entry to check tags
                if let Some(ref filter) = tag_filter {
                    if let Some(ref key) = profile_key {
                        // Read the entry file
                        let file_path = entry_idx.path.clone();
                        let data = std::fs::read(&file_path)
                            .map_err(|e| err_msg!(Backend, "Failed to read entry file: {}", e))?;

                        // Decrypt and decode
                        let entry_file = EntryFile::decode(&data)?;
                        let tags = entry_file
                            .tags
                            .into_iter()
                            .map(|(is_plaintext, tag_name, tag_value)| {
                                if is_plaintext {
                                    Ok(EntryTag::Encrypted(
                                        String::from_utf8_lossy(&tag_name).to_string(),
                                        String::from_utf8_lossy(&tag_value).to_string(),
                                    ))
                                } else {
                                    let dec_name_bytes = key.decrypt_tag_name(tag_name)?;
                                    let dec_name =
                                        String::from_utf8_lossy(&dec_name_bytes.into_vec())
                                            .to_string();
                                    let dec_value_bytes = key.decrypt_tag_value(tag_value)?;
                                    let dec_value =
                                        String::from_utf8_lossy(&dec_value_bytes.into_vec())
                                            .to_string();
                                    Ok(EntryTag::Encrypted(dec_name, dec_value))
                                }
                            })
                            .collect::<Result<Vec<_>, Error>>()?;

                        // Check if tags match the filter
                        if !matches_tag_filter(&tags, &filter.query) {
                            continue;
                        }
                    }
                }

                count += 1;
            }

            Ok(count)
        })
    }

    fn fetch<'q>(
        &'q mut self,
        kind: EntryKind,
        category: &'q str,
        name: &'q str,
        _for_update: bool,
    ) -> BoxFuture<'q, Result<Option<Entry>, Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            let (_profile_id, profile_key) = self
                .backend
                .key_cache
                .get_profile(&self.profile)
                .await
                .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;

            let index = self
                .backend
                .index
                .read()
                .map_err(|_| err_msg!(Backend, "Failed to acquire read lock on index"))?;

            let entries = index
                .get(&self.profile)
                .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;

            // Find matching entry
            let entry_idx = entries
                .iter()
                .find(|e| e.kind == kind && e.category == category && e.name == name);

            let entry_idx = match entry_idx {
                Some(e) => e,
                None => return Ok(None),
            };

            let path = entry_idx.path.clone();
            drop(index); // Release lock before I/O

            // Read entry from file
            let mut file = File::open(&path)
                .map_err(|e| err_msg!(Backend, "Failed to open entry file: {}", e))?;

            let mut data = Vec::new();
            file.read_to_end(&mut data)
                .map_err(|e| err_msg!(Backend, "Failed to read entry file: {}", e))?;

            let entry_file = EntryFile::decode(&data)?;

            // Decrypt entry (category, name, value)
            let decrypted_category =
                profile_key.decrypt_entry_category(entry_file.category.clone())?;
            let decrypted_name = profile_key.decrypt_entry_name(entry_file.name.clone())?;

            let decrypted_value = profile_key.decrypt_entry_value(
                &entry_file.category,
                &entry_file.name,
                entry_file.value.clone(),
            )?;

            let mut tags = Vec::new();
            for (plaintext, tag_name, tag_value) in &entry_file.tags {
                let tag = if *plaintext {
                    EntryTag::Plaintext(
                        String::from_utf8_lossy(tag_name).to_string(),
                        String::from_utf8_lossy(tag_value).to_string(),
                    )
                } else {
                    let dec_name_bytes = profile_key.decrypt_tag_name(tag_name.clone())?;
                    let dec_name = String::from_utf8_lossy(&dec_name_bytes.into_vec()).to_string();
                    let dec_value_bytes = profile_key.decrypt_tag_value(tag_value.clone())?;
                    let dec_value =
                        String::from_utf8_lossy(&dec_value_bytes.into_vec()).to_string();
                    EntryTag::Encrypted(dec_name, dec_value)
                };
                tags.push(tag);
            }

            let entry = Entry::new(
                entry_file.kind,
                decrypted_category,
                decrypted_name,
                decrypted_value,
                tags,
            );

            Ok(Some(entry))
        })
    }

    fn fetch_all<'q>(
        &'q mut self,
        kind: Option<EntryKind>,
        category: Option<&'q str>,
        tag_filter: Option<TagFilter>,
        limit: Option<i64>,
        _order_by: Option<OrderBy>,
        _descending: bool,
        _for_update: bool,
    ) -> BoxFuture<'q, Result<Vec<Entry>, Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            let (_profile_id, profile_key) = self
                .backend
                .key_cache
                .get_profile(&self.profile)
                .await
                .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;

            let index = self
                .backend
                .index
                .read()
                .map_err(|_| err_msg!(Backend, "Failed to acquire read lock on index"))?;

            let entries = index
                .get(&self.profile)
                .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?
                .clone();

            drop(index); // Release lock

            let mut results = Vec::new();
            let limit = limit.map(|l| l as usize);

            for entry_idx in entries {
                if let Some(k) = kind {
                    if entry_idx.kind != k {
                        continue;
                    }
                }

                if let Some(cat) = category {
                    if &entry_idx.category != cat {
                        continue;
                    }
                }

                // Read entry from file
                let mut file = File::open(&entry_idx.path)
                    .map_err(|e| err_msg!(Backend, "Failed to open entry file: {}", e))?;

                let mut data = Vec::new();
                file.read_to_end(&mut data)
                    .map_err(|e| err_msg!(Backend, "Failed to read entry file: {}", e))?;

                let entry_file = EntryFile::decode(&data)?;

                // Decrypt entry (category, name, value)
                let decrypted_category =
                    profile_key.decrypt_entry_category(entry_file.category.clone())?;
                let decrypted_name = profile_key.decrypt_entry_name(entry_file.name.clone())?;

                let decrypted_value = profile_key.decrypt_entry_value(
                    &entry_file.category,
                    &entry_file.name,
                    entry_file.value.clone(),
                )?;

                let mut tags = Vec::new();
                for (plaintext, tag_name, tag_value) in &entry_file.tags {
                    let tag = if *plaintext {
                        EntryTag::Plaintext(
                            String::from_utf8_lossy(tag_name).to_string(),
                            String::from_utf8_lossy(tag_value).to_string(),
                        )
                    } else {
                        let dec_name_bytes = profile_key.decrypt_tag_name(tag_name.clone())?;
                        let dec_name =
                            String::from_utf8_lossy(&dec_name_bytes.into_vec()).to_string();
                        let dec_value_bytes = profile_key.decrypt_tag_value(tag_value.clone())?;
                        let dec_value =
                            String::from_utf8_lossy(&dec_value_bytes.into_vec()).to_string();
                        EntryTag::Encrypted(dec_name, dec_value)
                    };
                    tags.push(tag);
                }

                // Apply tag filter
                if let Some(ref filter) = tag_filter {
                    if !matches_tag_filter(&tags, &filter.query) {
                        continue;
                    }
                }

                let entry = Entry::new(
                    entry_file.kind,
                    decrypted_category,
                    decrypted_name,
                    decrypted_value,
                    tags,
                );

                results.push(entry);

                if let Some(lim) = limit {
                    if results.len() >= lim {
                        break;
                    }
                }
            }

            Ok(results)
        })
    }

    fn remove_all<'q>(
        &'q mut self,
        _kind: Option<EntryKind>,
        _category: Option<&'q str>,
        _tag_filter: Option<TagFilter>,
    ) -> BoxFuture<'q, Result<i64, Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            // TODO: Implement remove_all
            Err(err_msg!(Unsupported, "remove_all not yet implemented"))
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
        _expiry_ms: Option<i64>,
    ) -> BoxFuture<'q, Result<(), Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            let (_profile_id, profile_key) = self
                .backend
                .key_cache
                .get_profile(&self.profile)
                .await
                .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;

            match operation {
                EntryOperation::Insert | EntryOperation::Replace => {
                    let value = value
                        .ok_or_else(|| err_msg!(Input, "Value required for insert/replace"))?;

                    // Check entry existence based on operation type
                    let index =
                        self.backend.index.read().map_err(|_| {
                            err_msg!(Backend, "Failed to acquire read lock on index")
                        })?;

                    let entries = index
                        .get(&self.profile)
                        .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;

                    let entry_exists = entries
                        .iter()
                        .any(|e| e.kind == kind && e.category == category && e.name == name);

                    drop(index); // Release read lock

                    // Validate based on operation
                    match operation {
                        EntryOperation::Insert if entry_exists => {
                            return Err(err_msg!(Duplicate, "Entry already exists"));
                        }
                        EntryOperation::Replace if !entry_exists => {
                            return Err(err_msg!(NotFound, "Entry not found for replacement"));
                        }
                        _ => {} // Valid operation
                    }

                    // Encrypt data
                    let enc_category = profile_key
                        .encrypt_entry_category(SecretBytes::from(category.as_bytes()))?;
                    let enc_name =
                        profile_key.encrypt_entry_name(SecretBytes::from(name.as_bytes()))?;
                    let enc_value = profile_key.encrypt_entry_value(
                        &enc_category,
                        &enc_name,
                        SecretBytes::from(value),
                    )?;

                    let mut enc_tags = Vec::new();
                    if let Some(tags) = tags {
                        for tag in tags {
                            match tag {
                                EntryTag::Encrypted(tag_name, tag_value) => {
                                    let enc_tag_name = profile_key
                                        .encrypt_tag_name(SecretBytes::from(tag_name.as_bytes()))?;
                                    let enc_tag_value = profile_key.encrypt_tag_value(
                                        SecretBytes::from(tag_value.as_bytes()),
                                    )?;
                                    enc_tags.push((false, enc_tag_name, enc_tag_value));
                                }
                                EntryTag::Plaintext(tag_name, tag_value) => {
                                    enc_tags.push((
                                        true,
                                        tag_name.as_bytes().to_vec(),
                                        tag_value.as_bytes().to_vec(),
                                    ));
                                }
                            }
                        }
                    }

                    let entry_file = EntryFile {
                        kind,
                        category: enc_category,
                        name: enc_name,
                        value: enc_value,
                        tags: enc_tags,
                    };

                    let encoded = entry_file.encode()?;

                    // Write to file
                    let filename = FlatFileBackend::entry_filename(kind, category, name);
                    let entries_dir = self.backend.entries_dir(&self.profile);
                    let file_path = entries_dir.join(&filename);

                    // If in transaction mode, queue the operation
                    if self.transaction {
                        // Clone necessary data for the closure
                        let file_path_clone = file_path.clone();
                        let encoded_clone = encoded.clone();
                        let backend_clone = self.backend.clone();
                        let profile_clone = self.profile.clone();
                        let category_str = category.to_string();
                        let name_str = name.to_string();

                        self.pending_ops.push(Box::new(move || {
                            // Write file
                            let mut file = File::create(&file_path_clone).map_err(|e| {
                                err_msg!(Backend, "Failed to create entry file: {}", e)
                            })?;
                            file.write_all(&encoded_clone).map_err(|e| {
                                err_msg!(Backend, "Failed to write entry file: {}", e)
                            })?;

                            // Update index
                            let mut index = backend_clone.index.write().map_err(|_| {
                                err_msg!(Backend, "Failed to acquire write lock on index")
                            })?;

                            let entries = index
                                .get_mut(&profile_clone)
                                .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;

                            // Remove old entry if exists
                            entries.retain(|e| {
                                !(e.kind == kind
                                    && e.category == category_str
                                    && e.name == name_str)
                            });

                            // Add new entry
                            entries.push(EntryIndex {
                                path: file_path_clone,
                                kind,
                                category: category_str,
                                name: name_str,
                            });

                            Ok(())
                        }));
                    } else {
                        // Execute immediately (non-transactional mode)
                        let mut file = File::create(&file_path)
                            .map_err(|e| err_msg!(Backend, "Failed to create entry file: {}", e))?;

                        file.write_all(&encoded)
                            .map_err(|e| err_msg!(Backend, "Failed to write entry file: {}", e))?;

                        // Update index
                        let mut index = self.backend.index.write().map_err(|_| {
                            err_msg!(Backend, "Failed to acquire write lock on index")
                        })?;

                        let entries = index
                            .get_mut(&self.profile)
                            .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;

                        // Remove old entry if exists
                        entries.retain(|e| {
                            !(e.kind == kind && e.category == category && e.name == name)
                        });

                        // Add new entry
                        entries.push(EntryIndex {
                            path: file_path,
                            kind,
                            category: category.to_string(),
                            name: name.to_string(),
                        });
                    }
                }
                EntryOperation::Remove => {
                    if self.transaction {
                        // In transaction mode, queue the remove operation
                        let backend_clone = self.backend.clone();
                        let profile_clone = self.profile.clone();
                        let category_str = category.to_string();
                        let name_str = name.to_string();

                        self.pending_ops.push(Box::new(move || {
                            let mut index = backend_clone.index.write().map_err(|_| {
                                err_msg!(Backend, "Failed to acquire write lock on index")
                            })?;

                            let entries = index
                                .get_mut(&profile_clone)
                                .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;

                            if let Some(pos) = entries.iter().position(|e| {
                                e.kind == kind && e.category == category_str && e.name == name_str
                            }) {
                                let entry = entries.remove(pos);
                                drop(index); // Release lock before I/O

                                if entry.path.exists() {
                                    fs::remove_file(&entry.path).map_err(|e| {
                                        err_msg!(Backend, "Failed to remove entry file: {}", e)
                                    })?;
                                }
                            }
                            Ok(())
                        }));
                    } else {
                        // Execute immediately (non-transactional mode)
                        let mut index = self.backend.index.write().map_err(|_| {
                            err_msg!(Backend, "Failed to acquire write lock on index")
                        })?;

                        let entries = index
                            .get_mut(&self.profile)
                            .ok_or_else(|| err_msg!(NotFound, "Profile not found"))?;

                        if let Some(pos) = entries.iter().position(|e| {
                            e.kind == kind && e.category == category && e.name == name
                        }) {
                            let entry = entries.remove(pos);
                            drop(index); // Release lock before I/O

                            if entry.path.exists() {
                                fs::remove_file(&entry.path).map_err(|e| {
                                    err_msg!(Backend, "Failed to remove entry file: {}", e)
                                })?;
                            }
                        }
                    }
                }
            }

            Ok(())
        })
    }

    fn ping(&mut self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            Ok(())
        })
    }

    fn close(&mut self, commit: bool) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            refuse_freshness_deployment()?;
            if commit && self.transaction {
                // Execute pending operations
                for op in self.pending_ops.drain(..) {
                    op()?;
                }
            }
            Ok(())
        })
    }
}
