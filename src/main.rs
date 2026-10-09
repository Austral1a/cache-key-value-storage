// Copyright (C) 2026 Daniil Korzh
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see https://www.gnu.org/licenses/.

mod global_alloc;

#[global_allocator]
static GLOBAL: global_alloc::PoolAlloc = global_alloc::PoolAlloc::new();

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use cachkeystorage::api::{AppState, handle};
use cachkeystorage::ckv_io::Pool;
use cachkeystorage::config::Config;
use cachkeystorage::store::{LRU_HIT_SAMPLE, MemoryCache, StoreOptions};

fn main() {
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(4)
        .thread_stack_size(2 * 1024 * 1024)
        .enable_io()
        .enable_time()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async_main());
}

async fn async_main() {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("configuration error: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = run(config).await {
        eprintln!("server error: {err}");
        std::process::exit(1);
    }
}

async fn run(config: Config) -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let token_count = config.tokens.len();
    let max_conns = config.max_conns;
    let idle_timeout = config.idle_timeout;
    let replacement = config.replacement;
    let expiration = config.expiration;
    let max_keys = config.max_keys;
    let max_bytes = config.max_bytes;
    let capacity = config.capacity;
    let state = Arc::new(AppState {
        cache: Arc::new(MemoryCache::open(StoreOptions {
            max_value_bytes: config.max_value_bytes,
            capacity,
            max_keys,
            max_bytes,
            replacement,
            expiration,
            shards: None,
            hit_sample: if replacement.needs_hit() {
                LRU_HIT_SAMPLE
            } else {
                1
            },
        })),
        tokens: config.tokens.into(),
        max_value_bytes: config.max_value_bytes,
    });

    if config.ckv_listen == Some(config.listen) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CACHE_CKV_LISTEN must differ from CACHE_LISTEN",
        ));
    }

    let listener = TcpListener::bind(config.listen).await?;
    let addr = listener.local_addr()?;
    warn_unspecified_bind("CACHE_LISTEN", addr);
    let ckv_listener = match config.ckv_listen {
        Some(ckv_addr) => {
            let ckv_listener = TcpListener::bind(ckv_addr).await?;
            let bound = ckv_listener.local_addr()?;
            warn_unspecified_bind("CACHE_CKV_LISTEN", bound);
            tracing::info!(
                %bound,
                "ckv listening; plaintext AUTH, bind a private address"
            );
            Some(ckv_listener)
        }
        None => None,
    };
    tracing::info!(
        %addr,
        token_count,
        max_value_bytes = config.max_value_bytes,
        capacity,
        replacement = %replacement,
        expiration = %expiration,
        max_keys,
        max_bytes,
        max_conns,
        idle_timeout_secs = idle_timeout.as_secs(),
        "cache listening; terminate TLS at a reverse proxy before exposing this port"
    );

    let slots = Arc::new(Semaphore::new(max_conns));
    let ckv_socket = config.ckv_socket.clone();
    let ckv_pool = if ckv_listener.is_some() || ckv_socket.is_some() {
        Some(Pool::start(Arc::clone(&state), idle_timeout))
    } else {
        None
    };
    if let (Some(path), Some(pool)) = (ckv_socket, ckv_pool.clone()) {
        spawn_unix(path, pool, Arc::clone(&slots));
    }
    let mut shutdown = std::pin::pin!(shutdown_signal());
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received");
                break;
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                spawn_http(stream, Arc::clone(&state), Arc::clone(&slots), idle_timeout);
            }
            accepted = accept_ckv(&ckv_listener) => {
                let (stream, _) = accepted?;
                if let Some(pool) = &ckv_pool {
                    spawn_ckv(stream, Arc::clone(pool), Arc::clone(&slots));
                }
            }
        }
    }
    Ok(())
}

fn warn_unspecified_bind(var: &str, addr: SocketAddr) {
    if addr.ip().is_unspecified() {
        tracing::warn!(
            %addr,
            "{var} listens on all interfaces; bind a private address unless a proxy is in front"
        );
    }
}

fn take_conn_slot(slots: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    match Arc::clone(slots).try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            tracing::warn!("max connections reached; dropping accept");
            None
        }
    }
}

fn spawn_http(stream: TcpStream, state: Arc<AppState>, slots: Arc<Semaphore>, idle: Duration) {
    let Some(permit) = take_conn_slot(&slots) else {
        return;
    };
    let _ = stream.set_nodelay(true);
    tokio::spawn(async move {
        let io = TokioIo::new(stream);
        let service = service_fn(move |req| handle(state.clone(), req));
        let mut http = http1::Builder::new();
        http.keep_alive(true).max_buf_size(8 * 1024);
        if !idle.is_zero() {
            http.timer(TokioTimer::new())
                .header_read_timeout(Some(idle));
        }
        let _ = http.serve_connection(io, service).await;
        drop(permit);
    });
}

fn spawn_unix(path: PathBuf, pool: Arc<Pool>, slots: Arc<Semaphore>) {
    let _ = std::fs::remove_file(&path);
    let listener = match std::os::unix::net::UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(%err, path = %path.display(), "ckv unix bind");
            return;
        }
    };
    tracing::info!(path = %path.display(), "ckv unix listening");
    std::thread::Builder::new()
        .name("ckv-unix".to_owned())
        .stack_size(1024 * 1024)
        .spawn(move || {
            for accepted in listener.incoming() {
                let stream = match accepted {
                    Ok(stream) => stream,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => {
                        tracing::debug!(%err, "ckv unix accept");
                        continue;
                    }
                };
                let Some(permit) = take_conn_slot(&slots) else {
                    continue;
                };
                pool.submit_unix(stream, permit);
            }
        })
        .expect("ckv unix thread");
}

fn spawn_ckv(stream: TcpStream, pool: Arc<Pool>, slots: Arc<Semaphore>) {
    let Some(permit) = take_conn_slot(&slots) else {
        return;
    };
    let _ = stream.set_nodelay(true);
    let Ok(stream) = stream.into_std() else {
        return;
    };
    pool.submit_tcp(stream, permit);
}

async fn accept_ckv(
    listener: &Option<TcpListener>,
) -> io::Result<(tokio::net::TcpStream, std::net::SocketAddr)> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install terminate handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}
