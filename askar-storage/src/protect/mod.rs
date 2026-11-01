//! Storage encryption

use std::{collections::HashMap, sync::Arc};

use async_lock::RwLock;

pub mod kdf;

pub mod hmac_key;

mod pass_key;
pub use self::pass_key::PassKey;

mod profile_key;
pub use self::profile_key::ProfileKey;

mod store_key;
pub use self::store_key::{generate_raw_store_key, StoreKey, StoreKeyMethod, StoreKeyReference};

use crate::{
    crypto::buffer::SecretBytes,
    entry::{EncEntryTag, EntryTag},
    error::Error,
    future::unblock,
};

pub type ProfileId = i64;

#[derive(Debug)]
pub struct KeyCache {
    profile_info: RwLock<HashMap<String, (ProfileId, Arc<ProfileKey>)>>,
    /// Keys by profile name with the id and the SHA-256 of the wrapped key they came from.
    verified: RwLock<HashMap<String, (ProfileId, [u8; 32], Arc<ProfileKey>)>>,
    pub(crate) store_key: Arc<StoreKey>,
}

impl KeyCache {
    pub fn new(store_key: impl Into<Arc<StoreKey>>) -> Self {
        Self {
            profile_info: RwLock::new(HashMap::new()),
            verified: RwLock::new(HashMap::new()),
            store_key: store_key.into(),
        }
    }

    /// The key of the profile row `(pid, wrapped key)` just read from the database.
    ///
    /// A cached key is returned only for the same profile id and the same wrapped-key
    /// fingerprint it was unwrapped from; anything else is unwrapped (and thereby
    /// authenticated under the store key) again. The cache therefore never answers for a
    /// row it has not seen, whatever happened to the profile in between.
    pub(crate) async fn resolve_profile(
        &self,
        name: &str,
        pid: ProfileId,
        fingerprint: [u8; 32],
        ciphertext: Vec<u8>,
    ) -> Result<Arc<ProfileKey>, Error> {
        if let Some((cached_pid, cached_fingerprint, key)) = self.verified.read().await.get(name)
        {
            if *cached_pid == pid && *cached_fingerprint == fingerprint {
                return Ok(key.clone());
            }
        }
        let key = Arc::new(self.load_key(ciphertext).await?);
        self.verified
            .write()
            .await
            .insert(name.to_owned(), (pid, fingerprint, key.clone()));
        self.profile_info
            .write()
            .await
            .insert(name.to_owned(), (pid, key.clone()));
        Ok(key)
    }

    pub async fn load_key(&self, ciphertext: Vec<u8>) -> Result<ProfileKey, Error> {
        let store_key = self.store_key.clone();
        unblock(move || {
            let data = store_key
                .unwrap_data(ciphertext)
                .map_err(err_map!(Encryption, "Error decrypting profile key"))?;
            ProfileKey::from_slice(data.as_ref())
        })
        .await
    }

    pub fn add_profile_mut(&mut self, ident: String, pid: ProfileId, key: ProfileKey) {
        self.profile_info
            .get_mut()
            .insert(ident, (pid, Arc::new(key)));
    }

    pub async fn add_profile(&self, ident: String, pid: ProfileId, key: Arc<ProfileKey>) {
        self.profile_info.write().await.insert(ident, (pid, key));
    }

    #[cfg_attr(not(feature = "flatfile"), allow(dead_code))]
    pub async fn get_profile(&self, name: &str) -> Option<(ProfileId, Arc<ProfileKey>)> {
        self.profile_info.read().await.get(name).cloned()
    }

    pub async fn clear_profile(&self, name: &str) {
        self.profile_info.write().await.remove(name);
        self.verified.write().await.remove(name);
    }
}

pub(crate) trait EntryEncryptor {
    fn prepare_input(input: &[u8]) -> SecretBytes {
        SecretBytes::from(input)
    }

    fn encrypt_entry_category(&self, category: SecretBytes) -> Result<Vec<u8>, Error>;
    fn encrypt_entry_name(&self, name: SecretBytes) -> Result<Vec<u8>, Error>;
    fn encrypt_entry_value(
        &self,
        category: &[u8],
        name: &[u8],
        value: SecretBytes,
    ) -> Result<Vec<u8>, Error>;
    fn encrypt_entry_tags(&self, tags: Vec<EntryTag>) -> Result<Vec<EncEntryTag>, Error>;

    fn decrypt_entry_category(&self, enc_category: Vec<u8>) -> Result<String, Error>;
    fn decrypt_entry_name(&self, enc_name: Vec<u8>) -> Result<String, Error>;
    fn decrypt_entry_value(
        &self,
        category: &[u8],
        name: &[u8],
        enc_value: Vec<u8>,
    ) -> Result<SecretBytes, Error>;
    fn decrypt_entry_tags(&self, enc_tags: Vec<EncEntryTag>) -> Result<Vec<EntryTag>, Error>;
}
