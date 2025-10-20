#[cfg(feature = "flatfile")]
mod flatfile_tests {
    use askar_storage::{
        backend::{flatfile::FlatFileStoreOptions, Backend, BackendSession, ManageBackend},
        entry::{EntryKind, EntryOperation, EntryTag},
        generate_raw_store_key,
        StoreKeyMethod,
    };
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_flatfile_provision_and_open() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test_store");

        // Generate a proper raw store key
        let raw_key = generate_raw_store_key(None).unwrap();

        // Provision a new store
        let options = FlatFileStoreOptions::new(&store_path);
        let backend = options
            .provision_backend(
                StoreKeyMethod::RawKey,
                raw_key.as_ref(),
                Some("default".to_string()),
                false,
            )
            .await
            .expect("Failed to provision store");

        // Verify basic properties
        assert_eq!(backend.get_active_profile(), "default");
        assert_eq!(
            backend.get_default_profile().await.unwrap(),
            "default"
        );

        let profiles = backend.list_profiles().await.unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0], "default");

        backend.close().await.unwrap();

        // Re-open the store with the same key
        let options = FlatFileStoreOptions::new(&store_path);
        let backend = options
            .open_backend(None, raw_key.as_ref(), None)
            .await
            .expect("Failed to open store");

        assert_eq!(backend.get_active_profile(), "default");
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_flatfile_crud_operations() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test_store");

        // Generate a proper raw store key
        let raw_key = generate_raw_store_key(None).unwrap();

        // Provision a new store
        let options = FlatFileStoreOptions::new(&store_path);
        let backend = options
            .provision_backend(
                StoreKeyMethod::RawKey,
                raw_key.as_ref(),
                Some("default".to_string()),
                false,
            )
            .await
            .expect("Failed to provision store");

        // Create a session
        let mut session = backend.session(None, false).unwrap();

        // Insert an entry
        session
            .update(
                EntryKind::Item,
                EntryOperation::Insert,
                "test_category",
                "test_name",
                Some(b"test_value"),
                Some(&[EntryTag::Encrypted(
                    "tag1".to_string(),
                    "value1".to_string(),
                )]),
                None,
            )
            .await
            .expect("Failed to insert entry");

        // Fetch the entry
        let entry = session
            .fetch(EntryKind::Item, "test_category", "test_name", false)
            .await
            .expect("Failed to fetch entry");

        assert!(entry.is_some());
        let entry = entry.unwrap();
        assert_eq!(entry.category, "test_category");
        assert_eq!(entry.name, "test_name");
        assert_eq!(entry.value.as_ref(), b"test_value");
        assert_eq!(entry.tags.len(), 1);

        // Count entries
        let count = session
            .count(Some(EntryKind::Item), Some("test_category"), None)
            .await
            .expect("Failed to count entries");

        assert_eq!(count, 1);

        // Update the entry
        session
            .update(
                EntryKind::Item,
                EntryOperation::Replace,
                "test_category",
                "test_name",
                Some(b"updated_value"),
                Some(&[EntryTag::Encrypted(
                    "tag1".to_string(),
                    "updated_value1".to_string(),
                )]),
                None,
            )
            .await
            .expect("Failed to update entry");

        // Verify update
        let entry = session
            .fetch(EntryKind::Item, "test_category", "test_name", false)
            .await
            .expect("Failed to fetch updated entry")
            .unwrap();

        assert_eq!(entry.value.as_ref(), b"updated_value");

        // Delete the entry
        session
            .update(
                EntryKind::Item,
                EntryOperation::Remove,
                "test_category",
                "test_name",
                None,
                None,
                None,
            )
            .await
            .expect("Failed to delete entry");

        // Verify deletion
        let entry = session
            .fetch(EntryKind::Item, "test_category", "test_name", false)
            .await
            .expect("Failed to fetch after delete");

        assert!(entry.is_none());

        session.close(true).await.unwrap();
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_flatfile_fetch_all() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test_store");

        // Generate a proper raw store key
        let raw_key = generate_raw_store_key(None).unwrap();

        let options = FlatFileStoreOptions::new(&store_path);
        let backend = options
            .provision_backend(
                StoreKeyMethod::RawKey,
                raw_key.as_ref(),
                None,
                false,
            )
            .await
            .unwrap();

        let mut session = backend.session(None, false).unwrap();

        // Insert multiple entries
        for i in 0..5 {
            session
                .update(
                    EntryKind::Item,
                    EntryOperation::Insert,
                    "category",
                    &format!("entry_{}", i),
                    Some(format!("value_{}", i).as_bytes()),
                    None,
                    None,
                )
                .await
                .unwrap();
        }

        // Fetch all entries
        let entries = session
            .fetch_all(Some(EntryKind::Item), Some("category"), None, None, None, false, false)
            .await
            .unwrap();

        assert_eq!(entries.len(), 5);

        session.close(true).await.unwrap();
        backend.close().await.unwrap();
    }

    #[tokio::test]
    async fn test_flatfile_multiple_profiles() {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join("test_store");

        // Generate a proper raw store key
        let raw_key = generate_raw_store_key(None).unwrap();

        let options = FlatFileStoreOptions::new(&store_path);
        let backend = options
            .provision_backend(
                StoreKeyMethod::RawKey,
                raw_key.as_ref(),
                Some("profile1".to_string()),
                false,
            )
            .await
            .unwrap();

        // Create a second profile
        let profile2_name = backend.create_profile(Some("profile2".to_string())).await.unwrap();
        assert_eq!(profile2_name, "profile2");

        // Verify profiles
        let profiles = backend.list_profiles().await.unwrap();
        assert_eq!(profiles.len(), 2);
        assert!(profiles.contains(&"profile1".to_string()));
        assert!(profiles.contains(&"profile2".to_string()));

        backend.close().await.unwrap();
    }
}
