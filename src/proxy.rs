use std::{sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, StatusCode, Uri, Version, header, uri::PathAndQuery,
    },
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde_json::{Value, json};
use tokio::sync::Semaphore;

use crate::{
    audit::{self, AuthorizationDecision, RequestContext, UpstreamStatus},
    policy::PolicyEngine,
    tls::ReloadHealth,
};

const PROXY_VIA_ID: &str = "arkion-identity-proxy";
const IDENTITY_HEADER: &str = "x-arkion-client-spiffe";

type UpstreamClient = Client<HttpConnector, Body>;

#[derive(Clone)]
pub struct AppState {
    policy: Arc<PolicyEngine>,
    client: UpstreamClient,
    upstream_uri: Uri,
    upstream_authority: HeaderValue,
    upstream_timeout: Duration,
    max_request_body_bytes: usize,
    concurrency: Arc<Semaphore>,
    reload_health: Arc<ReloadHealth>,
}

impl AppState {
    pub fn new(
        policy: PolicyEngine,
        upstream_uri: &Uri,
        upstream_timeout: Duration,
        max_request_body_bytes: usize,
        max_in_flight_requests: usize,
        reload_health: Arc<ReloadHealth>,
    ) -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(true);
        connector.set_nodelay(true);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        let authority = upstream_uri
            .authority()
            .expect("configuration validates upstream authority")
            .as_str();
        Self {
            policy: Arc::new(policy),
            client,
            upstream_uri: upstream_uri.clone(),
            upstream_authority: HeaderValue::from_str(authority)
                .expect("URI authority is a valid Host header"),
            upstream_timeout,
            max_request_body_bytes,
            concurrency: Arc::new(Semaphore::new(max_in_flight_requests)),
            reload_health,
        }
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .fallback(proxy_request)
        .layer(middleware::from_fn_with_state(state.clone(), authorize))
        .layer(middleware::from_fn(audit::middleware))
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn readiness(State(state): State<AppState>) -> Response {
    if state.reload_health.is_valid() {
        json_response(
            StatusCode::OK,
            json!({
                "status": "ready",
                "tls_config_version": state.reload_health.version()
            }),
        )
    } else {
        json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "stale_tls_configuration"}),
        )
    }
}

async fn authorize(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let context = request.extensions().get::<RequestContext>().cloned();
    let Some(context) = context else {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "unknown",
        );
    };

    if request.method() == http::Method::GET
        && matches!(request.uri().path(), "/healthz" | "/readyz")
    {
        let mut response = next.run(request).await;
        response
            .extensions_mut()
            .insert(AuthorizationDecision::AllowInternal);
        return response;
    }

    let Some(path) = &context.canonical_path else {
        let mut response =
            error_response(StatusCode::BAD_REQUEST, "invalid_path", &context.request_id);
        response
            .extensions_mut()
            .insert(AuthorizationDecision::InvalidRequest);
        return response;
    };

    if !state
        .policy
        .is_allowed(&context.identity, request.method(), path)
    {
        let mut response = error_response(
            StatusCode::FORBIDDEN,
            "authorization_denied",
            &context.request_id,
        );
        response
            .extensions_mut()
            .insert(AuthorizationDecision::Deny);
        return response;
    }

    let mut response = next.run(request).await;
    response
        .extensions_mut()
        .insert(AuthorizationDecision::Allow);
    response
}

async fn proxy_request(State(state): State<AppState>, request: Request) -> Response {
    let context = request
        .extensions()
        .get::<RequestContext>()
        .cloned()
        .expect("audit middleware installs request context");

    if has_proxy_loop(request.headers()) {
        return error_response(
            StatusCode::LOOP_DETECTED,
            "proxy_loop_detected",
            &context.request_id,
        );
    }

    let _permit = match Arc::clone(&state.concurrency).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "concurrency_limit_exceeded",
                &context.request_id,
            );
        }
    };

    if request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > state.max_request_body_bytes)
    {
        return error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request_body_too_large",
            &context.request_id,
        );
    }

    let original_host = context.original_host.clone();
    let upstream_uri = upstream_uri_with_request_target(&state.upstream_uri, request.uri());
    let (mut parts, body) = request.into_parts();
    let body = match to_bytes(body, state.max_request_body_bytes).await {
        Ok(body) => body,
        Err(_) => {
            return error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_body_too_large",
                &context.request_id,
            );
        }
    };

    parts.uri = upstream_uri;
    // The cleartext upstream client intentionally speaks HTTP/1.1. Inbound
    // HTTP/2 requests carry Version::HTTP_2 and cannot be sent unchanged by
    // that client.
    parts.version = Version::HTTP_11;
    rewrite_request_headers(
        &mut parts.headers,
        &state.upstream_authority,
        &original_host,
        &context,
    );
    let upstream_request = Request::from_parts(parts, Body::from(body));

    let result = tokio::time::timeout(
        state.upstream_timeout,
        state.client.request(upstream_request),
    )
    .await;
    let upstream_response = match result {
        Err(_) => {
            return error_response(
                StatusCode::GATEWAY_TIMEOUT,
                "upstream_timeout",
                &context.request_id,
            );
        }
        Ok(Err(error)) => {
            // hyper-util's Display implementation exposes only the broad error
            // category, not the request URI, headers, or body.
            tracing::warn!(
                event = "upstream_request_failed",
                request_id = %context.request_id,
                reason = %error,
            );
            return error_response(
                StatusCode::BAD_GATEWAY,
                "upstream_unavailable",
                &context.request_id,
            );
        }
        Ok(Ok(response)) => response,
    };

    let upstream_status = upstream_response.status();
    let (mut parts, body) = upstream_response.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    append_via(&mut parts.headers);
    let mut response = Response::from_parts(parts, Body::new(body));
    response
        .extensions_mut()
        .insert(UpstreamStatus(upstream_status.as_u16()));
    response
}

fn upstream_uri_with_request_target(origin: &Uri, request_uri: &Uri) -> Uri {
    let mut parts = origin.clone().into_parts();
    parts.path_and_query = Some(
        request_uri
            .path_and_query()
            .cloned()
            .unwrap_or_else(|| PathAndQuery::from_static("/")),
    );
    Uri::from_parts(parts).expect("validated origin and request target form a valid URI")
}

fn rewrite_request_headers(
    headers: &mut HeaderMap,
    upstream_authority: &HeaderValue,
    original_host: &str,
    context: &RequestContext,
) {
    strip_hop_by_hop(headers);
    for name in [
        header::FORWARDED.as_str(),
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        IDENTITY_HEADER,
    ] {
        headers.remove(name);
    }
    headers.insert(header::HOST, upstream_authority.clone());
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&context.remote_addr.ip().to_string())
            .expect("IP address is a valid header value"),
    );
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    if !original_host.is_empty() {
        if let Ok(value) = HeaderValue::from_str(original_host) {
            headers.insert("x-forwarded-host", value);
        }
    }
    let for_value = if context.remote_addr.ip().is_ipv6() {
        format!("\"[{}]\"", context.remote_addr.ip())
    } else {
        context.remote_addr.ip().to_string()
    };
    let forwarded = format!(
        "for={for_value};proto=https;host=\"{}\"",
        original_host.replace(['\\', '"'], "")
    );
    if let Ok(value) = HeaderValue::from_str(&forwarded) {
        headers.insert(header::FORWARDED, value);
    }
    headers.insert(
        IDENTITY_HEADER,
        HeaderValue::from_str(&context.identity).expect("SPIFFE ID is a valid header value"),
    );
    append_via(headers);
}

pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let nominated = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect::<Vec<_>>();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
}

fn has_proxy_loop(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::VIA)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|entry| {
            entry
                .split_whitespace()
                .any(|part| part.eq_ignore_ascii_case(PROXY_VIA_ID))
        })
}

fn append_via(headers: &mut HeaderMap) {
    headers.append(
        header::VIA,
        HeaderValue::from_static("1.1 arkion-identity-proxy"),
    );
}

fn error_response(status: StatusCode, code: &'static str, request_id: &str) -> Response {
    json_response(status, json!({"error": code, "request_id": request_id}))
}

fn json_response(status: StatusCode, value: Value) -> Response {
    let mut response = Response::new(Body::from(value.to_string()));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_standard_and_connection_nominated_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("x-remove, keep-alive"),
        );
        headers.insert("x-remove", HeaderValue::from_static("secret"));
        headers.insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        headers.insert("x-keep", HeaderValue::from_static("ok"));
        strip_hop_by_hop(&mut headers);
        assert!(!headers.contains_key(header::CONNECTION));
        assert!(!headers.contains_key("x-remove"));
        assert!(!headers.contains_key(header::UPGRADE));
        assert_eq!(headers.get("x-keep").unwrap(), "ok");
    }

    #[test]
    fn detects_only_its_own_via_marker() {
        let mut headers = HeaderMap::new();
        headers.insert(header::VIA, HeaderValue::from_static("1.1 another-proxy"));
        assert!(!has_proxy_loop(&headers));
        headers.append(
            header::VIA,
            HeaderValue::from_static("1.1 arkion-identity-proxy"),
        );
        assert!(has_proxy_loop(&headers));
    }

    #[test]
    fn composes_upstream_uri_without_reparsing_the_request_target() {
        let origin = Uri::from_static("http://backend:8080/");
        let request = Uri::from_static("https://proxy.example/echo?mode=test");
        assert_eq!(
            upstream_uri_with_request_target(&origin, &request),
            "http://backend:8080/echo?mode=test"
        );
    }
}
