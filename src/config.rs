use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

use anyhow::{Context, Result, bail};
use http::Uri;

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8443";
const DEFAULT_UPSTREAM_URL: &str = "http://backend:8080";

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub upstream_uri: Uri,
    pub upstream_origin: String,
    pub server_cert_path: PathBuf,
    pub server_key_path: PathBuf,
    pub client_ca_path: PathBuf,
    pub policy_path: PathBuf,
    pub trust_reload_interval: Duration,
    pub tls_handshake_timeout: Duration,
    pub upstream_timeout: Duration,
    pub max_request_body_bytes: usize,
    pub max_in_flight_requests: usize,
    pub graceful_shutdown_timeout: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|name| env::var(name).ok())
    }

    fn from_lookup(mut get: impl FnMut(&str) -> Option<String>) -> Result<Self> {
        let listen_addr = value(&mut get, "LISTEN_ADDR", DEFAULT_LISTEN_ADDR)
            .parse()
            .context("LISTEN_ADDR must be a socket address")?;
        let upstream = value(&mut get, "UPSTREAM_URL", DEFAULT_UPSTREAM_URL);
        let upstream_uri = Uri::from_str(&upstream).context("UPSTREAM_URL is not a valid URI")?;
        let upstream_origin = validate_upstream(&upstream_uri, listen_addr)?;

        Ok(Self {
            listen_addr,
            upstream_uri,
            upstream_origin,
            server_cert_path: value(&mut get, "TLS_CERT_PATH", "/config/tls/server.crt").into(),
            server_key_path: value(&mut get, "TLS_KEY_PATH", "/config/tls/server.key").into(),
            client_ca_path: value(&mut get, "TLS_CLIENT_CA_PATH", "/config/tls/client-ca.pem")
                .into(),
            policy_path: value(&mut get, "POLICY_PATH", "/config/policy.json").into(),
            trust_reload_interval: duration_ms(&mut get, "TRUST_RELOAD_INTERVAL_MS", 2_000)?,
            tls_handshake_timeout: duration_ms(&mut get, "TLS_HANDSHAKE_TIMEOUT_MS", 5_000)?,
            upstream_timeout: duration_ms(&mut get, "UPSTREAM_TIMEOUT_MS", 5_000)?,
            max_request_body_bytes: positive_usize(&mut get, "MAX_REQUEST_BODY_BYTES", 1_048_576)?,
            max_in_flight_requests: positive_usize(&mut get, "MAX_IN_FLIGHT_REQUESTS", 256)?,
            graceful_shutdown_timeout: duration_secs(
                &mut get,
                "GRACEFUL_SHUTDOWN_TIMEOUT_SECS",
                10,
            )?,
        })
    }
}

fn value(get: &mut impl FnMut(&str) -> Option<String>, name: &str, default: &str) -> String {
    get(name).unwrap_or_else(|| default.to_owned())
}

fn positive_usize(
    get: &mut impl FnMut(&str) -> Option<String>,
    name: &str,
    default: usize,
) -> Result<usize> {
    let value = get(name)
        .map(|raw| {
            raw.parse::<usize>()
                .with_context(|| format!("{name} must be an integer"))
        })
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn duration_ms(
    get: &mut impl FnMut(&str) -> Option<String>,
    name: &str,
    default: u64,
) -> Result<Duration> {
    let millis = get(name)
        .map(|raw| {
            raw.parse::<u64>()
                .with_context(|| format!("{name} must be an integer"))
        })
        .transpose()?
        .unwrap_or(default);
    if millis == 0 {
        bail!("{name} must be greater than zero");
    }
    Ok(Duration::from_millis(millis))
}

fn duration_secs(
    get: &mut impl FnMut(&str) -> Option<String>,
    name: &str,
    default: u64,
) -> Result<Duration> {
    let seconds = get(name)
        .map(|raw| {
            raw.parse::<u64>()
                .with_context(|| format!("{name} must be an integer"))
        })
        .transpose()?
        .unwrap_or(default);
    if seconds == 0 {
        bail!("{name} must be greater than zero");
    }
    Ok(Duration::from_secs(seconds))
}

fn validate_upstream(uri: &Uri, listen_addr: SocketAddr) -> Result<String> {
    if uri.scheme_str() != Some("http") {
        bail!("UPSTREAM_URL must use http; terminate upstream TLS separately if required");
    }
    let authority = uri
        .authority()
        .context("UPSTREAM_URL must include a host")?;
    if authority.as_str().contains('@') {
        bail!("UPSTREAM_URL must not contain user information");
    }
    if uri.query().is_some() || !matches!(uri.path(), "" | "/") {
        bail!("UPSTREAM_URL must be an origin without a path or query");
    }

    let upstream_port = authority.port_u16().unwrap_or(80);
    let host = authority.host();
    let local_host =
        matches!(host, "localhost" | "127.0.0.1" | "::1") || host == listen_addr.ip().to_string();
    if local_host && upstream_port == listen_addr.port() {
        bail!("UPSTREAM_URL points back to the proxy listener");
    }

    Ok(format!("http://{authority}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config(values: &[(&str, &str)]) -> Result<Config> {
        let values = values
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<HashMap<_, _>>();
        Config::from_lookup(|name| values.get(name).cloned())
    }

    #[test]
    fn rejects_an_obvious_proxy_loop() {
        let error = config(&[
            ("LISTEN_ADDR", "127.0.0.1:8443"),
            ("UPSTREAM_URL", "http://localhost:8443"),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("back to the proxy"));
    }

    #[test]
    fn rejects_upstream_paths() {
        assert!(config(&[("UPSTREAM_URL", "http://backend:8080/api")]).is_err());
    }

    #[test]
    fn parses_bounded_defaults() {
        let config = config(&[]).unwrap();
        assert_eq!(config.max_request_body_bytes, 1_048_576);
        assert_eq!(config.max_in_flight_requests, 256);
    }
}
