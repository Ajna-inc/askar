//! Fixtures for cancelling Askar storage futures at an exact point.
//!
//! PostgreSQL: [`HoldProxy`] sits between the pool and the server. When a
//! client message containing an armed marker (`COMMIT`, `BEGIN`, ...) passes,
//! it stops forwarding server bytes *before* forwarding that message, so the
//! statement reaches the server while its reply cannot reach the client. That
//! is the synchronization barrier: the future is dropped while provably
//! waiting for that reply, never because a timer happened to fire.
//!
//! SQLite: a second, raw connection holds a SHARED lock in rollback-journal
//! mode, so the pooled connection's COMMIT blocks inside SQLite until the
//! reader releases it (see [`SqliteReader`]).
#![allow(dead_code)]

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use sqlx::Connection;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

pub struct HoldProxy {
    addr: SocketAddr,
    state: Arc<ProxyState>,
}

struct ProxyState {
    armed: Mutex<Option<Vec<u8>>>,
    held: watch::Sender<bool>,
    connections: AtomicUsize,
}

impl HoldProxy {
    pub async fn start(upstream: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(ProxyState {
            armed: Mutex::new(None),
            held: watch::channel(false).0,
            connections: AtomicUsize::new(0),
        });
        let accept_state = state.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let server = TcpStream::connect(upstream).await.unwrap();
                accept_state.connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(relay(client, server, accept_state.clone()));
            }
        });
        Self { addr, state }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Server connections opened through the proxy so far.
    pub fn connections(&self) -> usize {
        self.state.connections.load(Ordering::SeqCst)
    }

    /// Hold server replies once a client message containing `marker` passes.
    pub fn arm(&self, marker: &str) {
        *self.state.armed.lock().unwrap() = Some(marker.as_bytes().to_vec());
    }

    pub async fn held(&self) {
        let mut rx = self.state.held.subscribe();
        rx.wait_for(|held| *held).await.unwrap();
    }

    pub fn release(&self) {
        self.state.held.send_replace(false);
    }
}

async fn relay(client: TcpStream, server: TcpStream, state: Arc<ProxyState>) {
    let (mut client_rd, mut client_wr) = client.into_split();
    let (mut server_rd, mut server_wr) = server.into_split();
    let upstream_state = state.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match client_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            {
                let mut armed = upstream_state.armed.lock().unwrap();
                if armed
                    .as_ref()
                    .is_some_and(|m| buf[..n].windows(m.len()).any(|w| w == m.as_slice()))
                {
                    *armed = None;
                    // Hold replies before the statement can reach the server.
                    upstream_state.held.send_replace(true);
                }
            }
            if server_wr.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = server_wr.shutdown().await;
    });
    let mut released = state.held.subscribe();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match server_rd.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        if released.wait_for(|held| !*held).await.is_err() {
            break;
        }
        if client_wr.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = client_wr.shutdown().await;
}

/// Runner URI → (proxied URI with a one-connection pool in its own schema,
/// direct URI for inspection, upstream address).
pub fn postgres_uris(proxy: Option<SocketAddr>, schema: &str) -> (String, String, SocketAddr) {
    let raw = std::env::var("TENANT_FENCE_TEST_POSTGRES")
        .expect("TENANT_FENCE_TEST_POSTGRES must name a disposable database");
    let mut url = url::Url::parse(&raw).expect("database URL");
    let upstream: SocketAddr = format!(
        "{}:{}",
        url.host_str().expect("host"),
        url.port().unwrap_or(5432)
    )
    .parse()
    .expect("the runner provides a numeric host");
    let direct = {
        let mut direct = url.clone();
        direct.set_query(None);
        direct.to_string()
    };
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "schema" && k != "max_connections" && k != "min_connections")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    {
        let mut query = url.query_pairs_mut();
        query.clear();
        for (k, v) in &pairs {
            query.append_pair(k, v);
        }
        query.append_pair("schema", schema);
        query.append_pair("max_connections", "1");
        query.append_pair("min_connections", "0");
    }
    if let Some(proxy) = proxy {
        url.set_port(Some(proxy.port())).unwrap();
    }
    (url.to_string(), direct, upstream)
}

/// Server sessions of this database left inside a transaction.
pub async fn idle_in_transaction(direct: &str) -> i64 {
    let mut conn = sqlx::PgConnection::connect(direct).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity
         WHERE datname = current_database() AND pid <> pg_backend_pid()
           AND state LIKE 'idle in transaction%'",
    )
    .fetch_one(&mut conn)
    .await
    .unwrap();
    conn.close().await.unwrap();
    count
}

/// A raw SQLite connection holding a SHARED lock (rollback-journal mode), so a
/// pooled writer's COMMIT waits inside SQLite until [`SqliteReader::release`].
pub struct SqliteReader(sqlx::SqliteConnection);

impl SqliteReader {
    pub async fn hold(path: &std::path::Path) -> Self {
        let url = format!("sqlite://{}", path.display());
        let mut conn = sqlx::SqliteConnection::connect(&url).await.unwrap();
        sqlx::query("BEGIN").execute(&mut conn).await.unwrap();
        let _: i64 = sqlx::query_scalar("SELECT count(*) FROM items")
            .fetch_one(&mut conn)
            .await
            .unwrap();
        Self(conn)
    }

    pub async fn release(mut self) {
        sqlx::query("ROLLBACK").execute(&mut self.0).await.unwrap();
        self.0.close().await.unwrap();
    }
}

/// Serializes the tests of this binary. `recovery_stats()` counts connection
/// repairs process-wide, so a test running in parallel could satisfy another
/// test's "this connection was repaired" assertion, or break its
/// "nothing was discarded" one (AUD-A F8). Hold the guard for the whole test.
pub async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    SERIAL.lock().await
}
