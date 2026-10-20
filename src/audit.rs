use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use axum::{body::Body, extract::Request, middleware::Next, response::Response};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Uri, header};
use http_body::{Body as HttpBody, Frame, SizeHint};
use uuid::Uuid;

use crate::{identity::ConnectionIdentity, policy::canonicalize_path};

const MAX_AUDIT_VALUE_BYTES: usize = 256;

#[derive(Clone, Debug)]
pub struct RequestContext {
    pub request_id: String,
    pub canonical_path: Option<String>,
    pub identity: String,
    pub remote_addr: std::net::SocketAddr,
    pub original_host: String,
}

#[derive(Clone, Copy, Debug)]
pub enum AuthorizationDecision {
    Allow,
    AllowInternal,
    Deny,
    InvalidRequest,
    Error,
}

#[derive(Clone, Copy, Debug)]
pub struct UpstreamStatus(pub u16);

impl AuthorizationDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::AllowInternal => "ALLOW_INTERNAL",
            Self::Deny => "DENY",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::Error => "ERROR",
        }
    }
}

pub async fn middleware(mut request: Request, next: Next) -> Response {
    let started = Instant::now();
    let connection = request.extensions().get::<ConnectionIdentity>().cloned();
    let identity = connection
        .as_ref()
        .map(|connection| connection.client.spiffe_id.clone())
        .unwrap_or_else(|| "unavailable".to_owned());
    let remote_addr = connection
        .as_ref()
        .map(|connection| connection.remote_addr)
        .unwrap_or_else(|| "0.0.0.0:0".parse().expect("static address is valid"));
    let request_id =
        accepted_request_id(request.headers()).unwrap_or_else(|| Uuid::new_v4().to_string());
    let canonical_path = canonicalize_path(request.uri().path()).ok();
    let method = request.method().as_str().to_owned();
    let path_for_log = canonical_path
        .clone()
        .unwrap_or_else(|| "<invalid>".to_owned());
    let host = request_host(request.uri(), request.headers());
    let content_type = safe_header(request.headers(), header::CONTENT_TYPE);
    let user_agent = safe_header(request.headers(), header::USER_AGENT);

    request.extensions_mut().insert(RequestContext {
        request_id: request_id.clone(),
        canonical_path,
        identity: identity.clone(),
        remote_addr,
        original_host: host.clone(),
    });
    request.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id).expect("generated request ID is a valid header"),
    );

    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id).expect("request ID was validated"),
    );
    let decision = response
        .extensions()
        .get::<AuthorizationDecision>()
        .copied()
        .unwrap_or(AuthorizationDecision::Error);
    let upstream_status = response
        .extensions()
        .get::<UpstreamStatus>()
        .map(|status| status.0)
        .unwrap_or(0);
    let status = response.status().as_u16();

    let response_has_body = method != "HEAD" && !matches!(status, 100..=199 | 204 | 304);
    let record = AuditRecord {
        started,
        request_id,
        identity,
        method,
        path: path_for_log,
        host,
        content_type,
        user_agent,
        decision,
        response_status: status,
        upstream_status,
    };
    let (parts, body) = response.into_parts();
    if !response_has_body {
        record.emit("complete");
        return Response::from_parts(parts, body);
    }
    Response::from_parts(parts, Body::new(AuditedBody::new(body, record)))
}

fn accepted_request_id(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("x-request-id")?.to_str().ok()?;
    if raw.is_empty()
        || raw.len() > 128
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(raw.to_owned())
}

fn safe_header(headers: &HeaderMap, name: impl http::header::AsHeaderName) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(safe_value)
        .unwrap_or_default()
}

fn request_host(uri: &Uri, headers: &HeaderMap) -> String {
    uri.authority()
        .map(|authority| safe_value(authority.as_str()))
        .unwrap_or_else(|| safe_header(headers, header::HOST))
}

fn safe_value(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(MAX_AUDIT_VALUE_BYTES)
        .collect()
}

struct AuditRecord {
    started: Instant,
    request_id: String,
    identity: String,
    method: String,
    path: String,
    host: String,
    content_type: String,
    user_agent: String,
    decision: AuthorizationDecision,
    response_status: u16,
    upstream_status: u16,
}

impl AuditRecord {
    fn emit(self, outcome: &'static str) {
        tracing::info!(
            event = "http_audit",
            request_id = %self.request_id,
            identity = %self.identity,
            method = %self.method,
            path = %self.path,
            host = %self.host,
            safe_content_type = %self.content_type,
            safe_user_agent = %self.user_agent,
            decision = self.decision.as_str(),
            response_status = self.response_status,
            upstream_status = self.upstream_status,
            latency_ms = self.started.elapsed().as_millis() as u64,
            response_body_outcome = outcome,
        );
    }
}

struct AuditedBody {
    inner: Pin<Box<Body>>,
    record: Option<AuditRecord>,
}

impl AuditedBody {
    fn new(inner: Body, record: AuditRecord) -> Self {
        Self {
            inner: Box::pin(inner),
            record: Some(record),
        }
    }

    fn finish(&mut self, outcome: &'static str) {
        if let Some(record) = self.record.take() {
            record.emit(outcome);
        }
    }
}

impl HttpBody for AuditedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.inner.as_mut().poll_frame(context) {
            Poll::Ready(None) => {
                self.finish("complete");
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                self.finish("body_error");
                Poll::Ready(Some(Err(error)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        // Keep this false until poll_frame observes EOS so even an empty body
        // emits a completed audit event rather than looking client-aborted.
        self.record.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for AuditedBody {
    fn drop(&mut self) {
        self.finish("client_aborted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn accepts_only_log_safe_request_ids() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("safe_id-1.2"));
        assert_eq!(
            accepted_request_id(&headers).as_deref(),
            Some("safe_id-1.2")
        );

        headers.insert("x-request-id", HeaderValue::from_static("contains space"));
        assert!(accepted_request_id(&headers).is_none());
    }

    #[test]
    fn gets_host_from_http2_authority_or_http1_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("http1.example"));
        assert_eq!(
            request_host(&Uri::from_static("/path"), &headers),
            "http1.example"
        );
        assert_eq!(
            request_host(
                &Uri::from_static("https://http2.example:8443/path"),
                &headers
            ),
            "http2.example:8443"
        );
    }
}
