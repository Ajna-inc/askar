//! Disposable JSON-lines fixture for real storage freshness acceptance.
//! No production account seeds, credentials or values are emitted.
use askar_storage::{
    backend::{
        freshness::PostgresWitness,
        postgres::{PostgresBackend, PostgresStoreOptions},
        sqlite::{SqliteBackend, SqliteStoreOptions},
    },
    entry::{EntryKind, EntryOperation},
    Backend, BackendSession, PassKey, StoreKeyMethod,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{self, BufRead, Write},
    path::Path,
};

enum Store {
    Sqlite(SqliteBackend),
    Postgres(PostgresBackend),
}

fn pg_uri(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let name = Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("Missing database name")?
        .replace('-', "_");
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err("Invalid fixture database name".into());
    }
    Ok(format!(
        "{}/{}",
        std::env::var("ASKAR_FIXTURE_PG_BASE_URL")?.trim_end_matches('/'),
        name
    ))
}
async fn seed<B: Backend>(backend: &B) -> Result<(), askar_storage::Error> {
    let mut session = backend.session(None, true)?;
    session
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            "freshness-fixture",
            "state",
            Some(b"initial"),
            None,
            None,
        )
        .await?;
    session.close(true).await
}
async fn probe<B: Backend>(
    backend: &mut B,
    request: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let op = request["op"].as_str().ok_or("Missing operation")?;
    match op {
        "read" => {
            let mut session = backend.session(None, false)?;
            let found = session
                .fetch(EntryKind::Item, "freshness-fixture", "state", false)
                .await?
                .is_some();
            session.close(false).await?;
            Ok(json!({"ok":true,"found":found}))
        }
        "write" | "rollback" | "implicit" => {
            let mut session = backend.session(None, op != "implicit")?;
            session
                .update(
                    EntryKind::Item,
                    EntryOperation::Replace,
                    "freshness-fixture",
                    "state",
                    Some(b"changed"),
                    None,
                    None,
                )
                .await?;
            session.close(op != "rollback").await?;
            Ok(json!({"ok":true}))
        }
        "remove_all" => {
            let mut session =
                backend.session(None, request["transaction"].as_bool().unwrap_or(false))?;
            session
                .remove_all(Some(EntryKind::Item), Some("freshness-fixture"), None)
                .await?;
            session.close(true).await?;
            Ok(json!({"ok":true}))
        }
        "profile_lifecycle" => {
            let same_name = request["same_name"].as_bool().unwrap_or(false);
            let original = if same_name {
                "lifecycle-same"
            } else {
                "lifecycle-a"
            };
            let replacement = if same_name { original } else { "lifecycle-b" };
            backend.create_profile(Some(original.into())).await?;
            let mut retained = backend.session(Some(original.into()), false)?;
            retained
                .update(
                    EntryKind::Item,
                    EntryOperation::Insert,
                    "freshness-fixture",
                    "retained",
                    Some(b"original"),
                    None,
                    None,
                )
                .await?;
            let was_active = retained
                .fetch(EntryKind::Item, "freshness-fixture", "retained", false)
                .await?
                .is_some();
            let removed = backend.remove_profile(original.into()).await?;
            backend.create_profile(Some(replacement.into())).await?;
            let read_refused = retained
                .fetch(EntryKind::Item, "freshness-fixture", "retained", false)
                .await
                .is_err();
            let write_refused = retained
                .update(
                    EntryKind::Item,
                    EntryOperation::Insert,
                    "freshness-fixture",
                    "pollution",
                    Some(b"old-key"),
                    None,
                    None,
                )
                .await
                .is_err();
            let _ = retained.close(false).await;
            let mut current = backend.session(Some(replacement.into()), false)?;
            current
                .update(
                    EntryKind::Item,
                    EntryOperation::Insert,
                    "freshness-fixture",
                    "current",
                    Some(b"current"),
                    None,
                    None,
                )
                .await?;
            let current_works = current
                .fetch(EntryKind::Item, "freshness-fixture", "current", false)
                .await?
                .is_some();
            current.close(false).await?;
            Ok(
                json!({"ok":true,"was_active":was_active,"removed":removed,"retained_read_refused":read_refused,"retained_write_refused":write_refused,"current_works":current_works}),
            )
        }
        "cancel_commit" => {
            let mut session = backend.session(None, true)?;
            session
                .update(
                    EntryKind::Item,
                    EntryOperation::Replace,
                    "freshness-fixture",
                    "state",
                    Some(b"cancelled"),
                    None,
                    None,
                )
                .await?;
            // Let the runner lock the independent witness only after validation
            // and staging have completed, so cancellation lands inside CAS.
            println!("{}", json!({"event":"staged"}));
            io::stdout().flush()?;
            let release = request["release_path"]
                .as_str()
                .ok_or("Missing fault coordination path")?;
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while !Path::new(release).exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await?;
            let cancelled =
                tokio::time::timeout(std::time::Duration::from_millis(100), session.close(true))
                    .await
                    .is_err();
            let read_refused = session
                .fetch(EntryKind::Item, "freshness-fixture", "state", false)
                .await
                .is_err();
            let commit_refused = session.close(true).await.is_err();
            Ok(
                json!({"ok":true,"cancelled":cancelled,"retained_read_refused":read_refused,"retained_commit_refused":commit_refused}),
            )
        }
        "insert" | "remove" | "missing_remove" => {
            let mut session = backend.session(None, false)?;
            let name = if op == "missing_remove" {
                "missing"
            } else {
                "state"
            };
            let operation = if op == "insert" {
                EntryOperation::Insert
            } else {
                EntryOperation::Remove
            };
            let value = if op == "insert" {
                Some(&b"reset"[..])
            } else {
                None
            };
            session
                .update(
                    EntryKind::Item,
                    operation,
                    "freshness-fixture",
                    name,
                    value,
                    None,
                    None,
                )
                .await?;
            session.close(true).await?;
            Ok(json!({"ok":true}))
        }
        "profile" => {
            let name = request["name"].as_str().unwrap_or("extra");
            backend.create_profile(Some(name.into())).await?;
            Ok(json!({"ok":true}))
        }
        "profile_remove" => {
            let name = request["name"].as_str().unwrap_or("extra");
            let removed = backend.remove_profile(name.into()).await?;
            Ok(json!({"ok":true,"removed":removed}))
        }
        "rename" => {
            backend
                .rename_profile("default".into(), "renamed".into())
                .await?;
            Ok(json!({"ok":true}))
        }
        "default" => {
            backend.set_default_profile("default".into()).await?;
            Ok(json!({"ok":true}))
        }
        "rekey" => {
            backend
                .rekey(StoreKeyMethod::Unprotected, PassKey::default())
                .await?;
            Ok(json!({"ok":true}))
        }
        _ => Err("Unknown operation".into()),
    }
}
async fn warmed_cache<B: Backend>(
    observer: &B,
    writer: &B,
) -> Result<Value, Box<dyn std::error::Error>> {
    let name = "independent-cache";
    writer.create_profile(Some(name.into())).await?;
    let mut warm = observer.session(Some(name.into()), false)?;
    warm.update(
        EntryKind::Item,
        EntryOperation::Insert,
        "freshness-fixture",
        "warm",
        Some(b"warm"),
        None,
        None,
    )
    .await?;
    let warmed = warm
        .fetch(EntryKind::Item, "freshness-fixture", "warm", false)
        .await?
        .is_some();
    warm.close(false).await?;
    let mut pending = observer.session(Some(name.into()), false)?;
    writer.remove_profile(name.into()).await?;
    writer.create_profile(Some(name.into())).await?;
    pending
        .update(
            EntryKind::Item,
            EntryOperation::Insert,
            "freshness-fixture",
            "fresh-key",
            Some(b"current"),
            None,
            None,
        )
        .await?;
    let pending_works = pending
        .fetch(EntryKind::Item, "freshness-fixture", "fresh-key", false)
        .await?
        .is_some();
    pending.close(false).await?;
    let mut current = writer.session(Some(name.into()), false)?;
    let current_reads = current
        .fetch(EntryKind::Item, "freshness-fixture", "fresh-key", false)
        .await?
        .is_some();
    current.close(false).await?;
    Ok(
        json!({"ok":true,"warmed":warmed,"pending_works":pending_works,"current_reads":current_reads}),
    )
}
async fn execute(
    request: &Value,
    stores: &mut HashMap<String, Store>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let op = request["op"].as_str().ok_or("Missing operation")?;
    let handle = request["handle"].as_str().unwrap_or("current");
    let postgres = std::env::var("ASKAR_FIXTURE_BACKEND").as_deref() == Ok("postgres");
    match op {
        "init" => {
            if std::env::var_os("ASKAR_FRESHNESS_LINEAGE").is_some() {
                return Err("Bootstrap must be explicit and unbound".into());
            }
            let path = request["path"].as_str().ok_or("Missing path")?;
            let backend = if postgres {
                Store::Postgres(
                    PostgresStoreOptions::new(pg_uri(path)?.as_str())?
                        .provision(
                            StoreKeyMethod::Unprotected,
                            PassKey::default(),
                            Some("default".into()),
                            false,
                        )
                        .await?,
                )
            } else {
                Store::Sqlite(
                    SqliteStoreOptions::from_path(path)
                        .provision(
                            StoreKeyMethod::Unprotected,
                            PassKey::default(),
                            Some("default".into()),
                            false,
                        )
                        .await?,
                )
            };
            let witness =
                PostgresWitness::connect(&std::env::var("ASKAR_FRESHNESS_WITNESS_URL")?).await?;
            witness.provision().await?;
            let head = match &backend {
                Store::Sqlite(b) => {
                    seed(b).await?;
                    b.bind_freshness(&witness).await?
                }
                Store::Postgres(b) => {
                    seed(b).await?;
                    b.bind_freshness(&witness).await?
                }
            };
            std::env::set_var("ASKAR_FRESHNESS_LINEAGE", head.lineage.to_string());
            stores.insert(handle.into(), backend);
            Ok(json!({"ok":true,"lineage":head.lineage}))
        }
        "open" => {
            let path = request["path"].as_str().unwrap_or("");
            let backend = if postgres {
                let uri = match request["uri"].as_str() {
                    Some(uri) => uri.to_owned(),
                    None => pg_uri(path)?,
                };
                Store::Postgres(
                    PostgresStoreOptions::new(uri.as_str())?
                        .open(None, PassKey::default(), Some("default".into()))
                        .await?,
                )
            } else {
                let options = match request["uri"].as_str() {
                    Some(uri) => SqliteStoreOptions::new(uri)?,
                    None => SqliteStoreOptions::from_path(path),
                };
                Store::Sqlite(
                    options
                        .open(None, PassKey::default(), Some("default".into()))
                        .await?,
                )
            };
            stores.insert(handle.into(), backend);
            Ok(json!({"ok":true}))
        }
        "warmed_cache" => {
            let observer = stores.remove("cache-observer").ok_or("Missing observer")?;
            let writer = stores.get(handle).ok_or("Missing writer")?;
            let result = match (&observer, writer) {
                (Store::Sqlite(a), Store::Sqlite(b)) => warmed_cache(a, b).await,
                (Store::Postgres(a), Store::Postgres(b)) => warmed_cache(a, b).await,
                _ => Err("Mixed fixture backend".into()),
            };
            stores.insert("cache-observer".into(), observer);
            result
        }
        "close" => {
            match stores.remove(handle).ok_or("Unknown handle")? {
                Store::Sqlite(b) => b.close().await?,
                Store::Postgres(b) => b.close().await?,
            };
            Ok(json!({"ok":true}))
        }
        _ => match stores.get_mut(handle).ok_or("Unknown handle")? {
            Store::Sqlite(b) => probe(b, request).await,
            Store::Postgres(b) => probe(b, request).await,
        },
    }
}
#[tokio::main]
async fn main() {
    let mut stores = HashMap::new();
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let response = match line {
            Ok(line) => match serde_json::from_str::<Value>(&line) {
                Ok(request) => match execute(&request, &mut stores).await {
                    Ok(value) => value,
                    Err(error) => {
                        let text = error.to_string().to_ascii_lowercase();
                        let refusal = if text.contains("freshness") || text.contains("witness") {
                            "freshness"
                        } else if text.contains("bound store") {
                            "unsupported_bound_operation"
                        } else {
                            "fixture_error"
                        };
                        json!({"ok":false,"refusal":refusal})
                    }
                },
                Err(_) => json!({"ok":false,"refusal":"fixture_error"}),
            },
            Err(_) => break,
        };
        println!("{response}");
        if io::stdout().flush().is_err() {
            break;
        }
    }
}
