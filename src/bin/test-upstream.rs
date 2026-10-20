use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::{Router, body::to_bytes, extract::Request, response::Json};
use serde_json::{Value, json};

#[tokio::main]
async fn main() -> Result<()> {
    let address = std::env::var("TEST_UPSTREAM_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:18080".to_owned())
        .parse::<SocketAddr>()
        .context("TEST_UPSTREAM_ADDR must be a socket address")?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, Router::new().fallback(echo)).await?;
    Ok(())
}

async fn echo(request: Request) -> Json<Value> {
    let method = request.method().to_string();
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(ToString::to_string)
        .unwrap_or_else(|| "/".to_owned());
    let headers = request.headers().clone();
    let body = to_bytes(request.into_body(), 1_048_576)
        .await
        .unwrap_or_default();
    Json(json!({
        "method": method,
        "path_and_query": path_and_query,
        "body": String::from_utf8_lossy(&body),
        "authorization_present": headers.contains_key("authorization"),
        "cookie_present": headers.contains_key("cookie"),
        "forwarded": headers.get("forwarded").and_then(|value| value.to_str().ok()),
        "x_forwarded_for": headers.get("x-forwarded-for").and_then(|value| value.to_str().ok()),
        "x_forwarded_host": headers.get("x-forwarded-host").and_then(|value| value.to_str().ok()),
        "x_forwarded_proto": headers.get("x-forwarded-proto").and_then(|value| value.to_str().ok()),
        "identity": headers.get("x-arkion-client-spiffe").and_then(|value| value.to_str().ok()),
        "connection_nominated_header_present": headers.contains_key("x-remove")
    }))
}
