use std::{
    io::{BufReader, Cursor},
    path::PathBuf,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, bail};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use tokio::{fs, sync::watch};

#[derive(Clone, Debug)]
pub struct TlsMaterialPaths {
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_ca: PathBuf,
}

#[derive(Clone)]
pub struct TlsConfigStore {
    current: Arc<RwLock<Arc<ServerConfig>>>,
}

pub struct ReloadHealth {
    valid: AtomicBool,
    version: AtomicU64,
}

#[derive(Clone, Eq, PartialEq)]
struct Material {
    server_cert: Vec<u8>,
    server_key: Vec<u8>,
    client_ca: Vec<u8>,
}

impl TlsConfigStore {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            current: Arc::new(RwLock::new(Arc::new(config))),
        }
    }

    pub fn current(&self) -> Arc<ServerConfig> {
        self.current
            .read()
            .expect("TLS configuration lock was poisoned")
            .clone()
    }

    fn replace(&self, config: ServerConfig) {
        *self
            .current
            .write()
            .expect("TLS configuration lock was poisoned") = Arc::new(config);
    }
}

impl ReloadHealth {
    pub fn new() -> Self {
        Self {
            valid: AtomicBool::new(true),
            version: AtomicU64::new(1),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }

    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }
}

impl Default for ReloadHealth {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn load_initial(paths: &TlsMaterialPaths) -> Result<(TlsConfigStore, MaterialGuard)> {
    let material = Material::read(paths).await?;
    let config = build_server_config(&material)?;
    Ok((TlsConfigStore::new(config), MaterialGuard { material }))
}

/// Watches complete TLS material snapshots. A candidate is parsed and validated
/// before the active Arc is replaced, so readers never observe a partial update.
pub async fn reload_loop(
    paths: TlsMaterialPaths,
    interval: Duration,
    store: TlsConfigStore,
    health: Arc<ReloadHealth>,
    mut shutdown: watch::Receiver<bool>,
    initial: MaterialGuard,
) {
    let mut active = initial.material;
    let mut observed = active.clone();
    let mut read_failed = false;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
            _ = ticker.tick() => {
                let candidate = match Material::read(&paths).await {
                    Ok(candidate) => candidate,
                    Err(error) => {
                        health.valid.store(false, Ordering::Release);
                        if !read_failed {
                            tracing::error!(event = "tls_reload_rejected", reason = %error);
                        }
                        read_failed = true;
                        continue;
                    }
                };
                read_failed = false;
                if candidate == observed {
                    if candidate == active {
                        health.valid.store(true, Ordering::Release);
                    }
                    continue;
                }
                // Mark this byte-for-byte candidate observed even if invalid. This
                // prevents log storms; a corrected or rolled-back file is different
                // and will be attempted on the next polling interval.
                observed = candidate.clone();
                match build_server_config(&candidate) {
                    Ok(config) => {
                        store.replace(config);
                        active = candidate;
                        health.valid.store(true, Ordering::Release);
                        let version = health.version.fetch_add(1, Ordering::AcqRel) + 1;
                        tracing::info!(event = "tls_reload_applied", tls_config_version = version);
                    }
                    Err(error) => {
                        health.valid.store(false, Ordering::Release);
                        tracing::error!(event = "tls_reload_rejected", reason = %error);
                    }
                }
            }
        }
    }
}

pub struct MaterialGuard {
    material: Material,
}

impl Material {
    async fn read(paths: &TlsMaterialPaths) -> Result<Self> {
        let (server_cert, server_key, client_ca) = tokio::try_join!(
            fs::read(&paths.server_cert),
            fs::read(&paths.server_key),
            fs::read(&paths.client_ca),
        )
        .with_context(|| "failed to read TLS material")?;
        Ok(Self {
            server_cert,
            server_key,
            client_ca,
        })
    }
}

fn build_server_config(material: &Material) -> Result<ServerConfig> {
    let certificates =
        rustls_pemfile::certs(&mut BufReader::new(Cursor::new(&material.server_cert)))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("server certificate PEM is malformed")?;
    if certificates.is_empty() {
        bail!("server certificate PEM contains no certificates");
    }

    let private_key =
        rustls_pemfile::private_key(&mut BufReader::new(Cursor::new(&material.server_key)))
            .context("server private key PEM is malformed")?
            .context("server private key PEM contains no supported key")?;

    let client_roots = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(&material.client_ca)))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("client CA bundle PEM is malformed")?;
    if client_roots.is_empty() {
        bail!("client CA bundle contains no certificates");
    }
    let mut roots = RootCertStore::empty();
    for certificate in client_roots {
        roots
            .add(certificate)
            .context("client CA bundle contains an invalid trust anchor")?;
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("failed to create required client-certificate verifier")?;
    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates, private_key)
        .context("server certificate and private key do not form a valid pair")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}
