//! Provisioning and management of flat file stores

use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};

use super::{
    FlatFileBackend, StoreConfig, CONFIG_FILE, ENTRIES_DIR, PROFILES_DIR, PROFILE_KEY_FILE,
    STORE_KEY_FILE,
};
use crate::{
    backend::ManageBackend,
    error::Error,
    future::{unblock, BoxFuture},
    protect::{KeyCache, PassKey, ProfileKey, StoreKey, StoreKeyMethod, StoreKeyReference},
};

/// Options for provisioning a flat file store
#[derive(Debug, Clone)]
pub struct FlatFileStoreOptions {
    /// Path to the store directory
    pub path: PathBuf,
}

impl FlatFileStoreOptions {
    /// Create a new set of store options
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Convert a path string to store options
    pub fn from_str(path: &str) -> Result<Self, Error> {
        Ok(Self::new(path))
    }
}

impl<'a> ManageBackend<'a> for FlatFileStoreOptions {
    type Backend = FlatFileBackend;

    fn open_backend(
        self,
        _method: Option<StoreKeyMethod>,
        pass_key: PassKey<'a>,
        profile: Option<String>,
    ) -> BoxFuture<'a, Result<Self::Backend, Error>> {
        Box::pin(async move {
            if !self.path.exists() {
                return Err(err_msg!(NotFound, "Store directory not found"));
            }

            // Read config
            let config_path = self.path.join(CONFIG_FILE);
            if !config_path.exists() {
                return Err(err_msg!(NotFound, "Store config not found"));
            }

            let config_data = fs::read_to_string(&config_path)
                .map_err(|e| err_msg!(Backend, "Failed to read config: {}", e))?;

            let config: StoreConfig = serde_json::from_str(&config_data)
                .map_err(|e| err_msg!(Backend, "Failed to parse config: {}", e))?;

            // Read store key
            let store_key_path = self.path.join(STORE_KEY_FILE);
            if !store_key_path.exists() {
                return Err(err_msg!(NotFound, "Store key not found"));
            }

            let store_key_ref_data = fs::read_to_string(&store_key_path)
                .map_err(|e| err_msg!(Backend, "Failed to read store key: {}", e))?;

            // Parse store key reference
            let store_key_ref = StoreKeyReference::parse_uri(&store_key_ref_data)?;
            let method: StoreKeyMethod = store_key_ref.into();

            // Resolve store key
            let (store_key, _) = method.resolve(pass_key)?;

            // Create key cache
            let mut key_cache = KeyCache::new(store_key.clone());

            // Determine active profile
            let active_profile = profile.unwrap_or_else(|| config.default_profile.clone());

            if !config.profiles.contains(&active_profile) {
                return Err(err_msg!(NotFound, "Profile not found: {}", active_profile));
            }

            // Load profile key
            let profile_dir = self.path.join(PROFILES_DIR).join(&active_profile);
            let profile_key_path = profile_dir.join(PROFILE_KEY_FILE);

            if !profile_key_path.exists() {
                return Err(err_msg!(NotFound, "Profile key not found"));
            }

            let enc_profile_key_data = fs::read(&profile_key_path)
                .map_err(|e| err_msg!(Backend, "Failed to read profile key: {}", e))?;

            // Decrypt profile key
            let profile_key_bytes = store_key.unwrap_data(enc_profile_key_data)?;
            let profile_key = ProfileKey::from_slice(&profile_key_bytes)?;

            // Use a simple counter for profile ID in file backend (0 for first profile)
            let profile_id = 0i64;

            key_cache.add_profile_mut(active_profile.clone(), profile_id, profile_key);

            // Create backend
            FlatFileBackend::new(self.path, active_profile, key_cache)
        })
    }

    fn provision_backend(
        self,
        method: StoreKeyMethod,
        pass_key: PassKey<'a>,
        profile: Option<String>,
        recreate: bool,
    ) -> BoxFuture<'a, Result<Self::Backend, Error>> {
        Box::pin(async move {
            // Check if store already exists
            if self.path.exists() {
                if recreate {
                    fs::remove_dir_all(&self.path)
                        .map_err(|e| err_msg!(Backend, "Failed to remove existing store: {}", e))?;
                } else {
                    return Err(err_msg!(Duplicate, "Store already exists"));
                }
            }

            // Create directory structure
            fs::create_dir_all(&self.path)
                .map_err(|e| err_msg!(Backend, "Failed to create store directory: {}", e))?;

            let profiles_dir = self.path.join(PROFILES_DIR);
            fs::create_dir_all(&profiles_dir)
                .map_err(|e| err_msg!(Backend, "Failed to create profiles directory: {}", e))?;

            // Generate store key and profile key
            let (store_key, store_key_ref, profile_key, enc_profile_key) = unblock({
                let pass_key = pass_key.into_owned();
                move || -> Result<(StoreKey, String, ProfileKey, Vec<u8>), Error> {
                    if method == StoreKeyMethod::RawKey && pass_key.is_empty() {
                        return Err(err_msg!(Input, "Cannot create a store with a blank raw key"));
                    }
                    let (store_key, store_key_ref) = method.resolve(pass_key)?;
                    let profile_key = ProfileKey::new()?;
                    let enc_profile_key = store_key.wrap_data(profile_key.to_bytes()?)?;
                    Ok((store_key, store_key_ref.into_uri(), profile_key, enc_profile_key))
                }
            }).await?;

            // Write store key reference
            let store_key_path = self.path.join(STORE_KEY_FILE);
            let mut file = fs::File::create(&store_key_path)
                .map_err(|e| err_msg!(Backend, "Failed to create store key file: {}", e))?;
            file.write_all(store_key_ref.as_bytes())
                .map_err(|e| err_msg!(Backend, "Failed to write store key: {}", e))?;

            // Create key cache
            let mut key_cache = KeyCache::new(store_key);

            // Create default profile
            let profile_name = profile.unwrap_or_else(|| "default".to_string());
            let profile_id = 0i64; // Simple counter for file backend

            let profile_dir = profiles_dir.join(&profile_name);
            fs::create_dir_all(&profile_dir)
                .map_err(|e| err_msg!(Backend, "Failed to create profile directory: {}", e))?;

            let entries_dir = profile_dir.join(ENTRIES_DIR);
            fs::create_dir_all(&entries_dir)
                .map_err(|e| err_msg!(Backend, "Failed to create entries directory: {}", e))?;

            // Write profile key
            let profile_key_path = profile_dir.join(PROFILE_KEY_FILE);

            let mut file = fs::File::create(&profile_key_path)
                .map_err(|e| err_msg!(Backend, "Failed to create profile key file: {}", e))?;
            file.write_all(&enc_profile_key)
                .map_err(|e| err_msg!(Backend, "Failed to write profile key: {}", e))?;

            // Add profile to key cache
            key_cache.add_profile_mut(profile_name.clone(), profile_id, profile_key);

            // Create config
            let config = StoreConfig {
                default_profile: profile_name.clone(),
                profiles: vec![profile_name.clone()],
                version: 1,
            };

            let config_path = self.path.join(CONFIG_FILE);
            let config_json = serde_json::to_string_pretty(&config)
                .map_err(|e| err_msg!(Backend, "Failed to serialize config: {}", e))?;

            let mut file = fs::File::create(&config_path)
                .map_err(|e| err_msg!(Backend, "Failed to create config file: {}", e))?;
            file.write_all(config_json.as_bytes())
                .map_err(|e| err_msg!(Backend, "Failed to write config: {}", e))?;

            // Create backend
            FlatFileBackend::new(self.path, profile_name, key_cache)
        })
    }

    fn remove_backend(self) -> BoxFuture<'a, Result<bool, Error>> {
        Box::pin(async move {
            if !self.path.exists() {
                return Ok(false);
            }

            fs::remove_dir_all(&self.path)
                .map_err(|e| err_msg!(Backend, "Failed to remove store: {}", e))?;

            Ok(true)
        })
    }
}
