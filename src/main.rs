use std::{sync::Arc, time::SystemTime};

use anyhow::{Context, Result};
use axum::{Extension, Router};
use hyper_util::service::TowerToHyperService;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use identity_aware_tls_rev_proxy::{
    AppState, ClientIdentity, Config, ConnectionIdentity, PolicyEngine, ReloadHealth,
    TlsMaterialPaths, build_router,
    tls::{load_initial, reload_loop},
};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
use tokio_rustls::TlsAcceptor;
use tower::ServiceBuilder;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("identity_aware_tls_rev_proxy=info"))
        // Dependency trace logs are disabled even when RUST_LOG is broad: an
        // implementation detail must not accidentally print headers or bodies.
        .add_directive("axum=off".parse().expect("static directive is valid"))
        .add_directive("h2=off".parse().expect("static directive is valid"))
        .add_directive("hyper=off".parse().expect("static directive is valid"))
        .add_directive("hyper_util=off".parse().expect("static directive is valid"))
        .add_directive("rustls=off".parse().expect("static directive is valid"))
        .add_directive("tower=off".parse().expect("static directive is valid"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_current_span(false)
        .with_span_list(false)
        .init();

    if let Err(error) = run().await {
        tracing::error!(event = "fatal_error", reason = %error);
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let config = Config::from_env()?;
    let policy = PolicyEngine::load(&config.policy_path)?;
    let paths = TlsMaterialPaths {
        server_cert: config.server_cert_path.clone(),
        server_key: config.server_key_path.clone(),
        client_ca: config.client_ca_path.clone(),
    };
    let (tls_store, initial_material) = load_initial(&paths).await?;
    let reload_health = Arc::new(ReloadHealth::new());
    let app = build_router(AppState::new(
        policy,
        &config.upstream_uri,
        config.upstream_timeout,
        config.max_request_body_bytes,
        config.max_in_flight_requests,
        Arc::clone(&reload_health),
    ));
    let listener = TcpListener::bind(config.listen_addr)
        .await
        .with_context(|| format!("failed to bind {}", config.listen_addr))?;
    tracing::info!(
        event = "proxy_started",
        listen_addr = %config.listen_addr,
        upstream = %config.upstream_origin,
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let reload_task = tokio::spawn(reload_loop(
        paths,
        config.trust_reload_interval,
        tls_store.clone(),
        reload_health,
        shutdown_rx.clone(),
        initial_material,
    ));
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!(event = "shutdown_requested");
        let _ = signal_tx.send(true);
    });

    let mut shutdown = shutdown_rx;
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, remote_addr)) => {
                        let app = app.clone();
                        let acceptor = TlsAcceptor::from(tls_store.current());
                        let connection_shutdown = shutdown.clone();
                        let handshake_timeout = config.tls_handshake_timeout;
                        connections.spawn(async move {
                            if let Err(error) = serve_connection(
                                stream,
                                remote_addr,
                                acceptor,
                                app,
                                connection_shutdown,
                                handshake_timeout,
                            ).await {
                                tracing::debug!(event = "connection_closed", remote_addr = %remote_addr, reason = %error);
                            }
                        });
                    }
                    Err(error) => tracing::warn!(event = "tcp_accept_failed", reason = %error),
                }
            }
        }
    }

    let drain = async { while connections.join_next().await.is_some() {} };
    if tokio::time::timeout(config.graceful_shutdown_timeout, drain)
        .await
        .is_err()
    {
        connections.abort_all();
        tracing::warn!(event = "graceful_shutdown_timed_out");
    }
    let _ = reload_task.await;
    tracing::info!(event = "proxy_stopped");
    Ok(())
}

async fn serve_connection(
    stream: tokio::net::TcpStream,
    remote_addr: std::net::SocketAddr,
    acceptor: TlsAcceptor,
    app: Router,
    mut shutdown: watch::Receiver<bool>,
    handshake_timeout: std::time::Duration,
) -> Result<()> {
    stream.set_nodelay(true)?;
    let tls = tokio::time::timeout(handshake_timeout, acceptor.accept(stream))
        .await
        .context("TLS handshake timed out")?
        .context("TLS handshake failed")?;
    let peer_chain = tls
        .get_ref()
        .1
        .peer_certificates()
        .context("TLS session has no validated client certificate")?;
    let client = ClientIdentity::from_validated_chain(peer_chain, SystemTime::now())
        .context("client identity extraction failed")?;
    let connection = ConnectionIdentity {
        client,
        remote_addr,
    };

    let service = ServiceBuilder::new()
        .layer(Extension(connection))
        .service(app);
    let service = TowerToHyperService::new(service);
    let io = TokioIo::new(tls);
    let builder = Builder::new(TokioExecutor::new());
    let connection = builder.serve_connection_with_upgrades(io, service);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result
            .map_err(|error| anyhow::anyhow!("HTTP connection failed: {error}"))?,
        changed = shutdown.changed() => {
            if changed.is_ok() && *shutdown.borrow() {
                connection.as_mut().graceful_shutdown();
                connection.await.map_err(|error| {
                    anyhow::anyhow!("HTTP connection failed during graceful shutdown: {error}")
                })?;
            }
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler must be installable");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .expect("Ctrl-C handler must be installable");
}
