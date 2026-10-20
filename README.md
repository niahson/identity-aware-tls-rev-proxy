# Identity-aware TLS reverse proxy

A Rust reverse proxy that authenticates non-human clients with mutual TLS, derives a canonical SPIFFE identity from the client certificate, applies deny-by-default authorization policy, emits secret-safe structured audit events, and forwards authorized HTTP traffic to an existing service.

## Request flow

```text
                         atomic TLS config snapshot
                                    |
client -- TLS/mTLS --> Rustls --> identity --> policy --> limits --> upstream
                         |             |          |          |          |
                    chain/time     SPIFFE URI   method +   timeout/   HTTP/1.1
                    validation     SAN parsing   path       bounds
                                      \________ audit after body ______/
```

The proxy listens on `https://0.0.0.0:8443` by default and forwards to `http://backend:8080`. Every public endpoint, including health endpoints, is behind required mTLS.

## Security properties

- Rustls requires a client certificate and validates its signature chain, trust anchor, validity period, key usage, and client-auth extended key usage before HTTP is accepted.
- Application code parses subject, issuer, URI/DNS SANs, serial number, validity, and every presented chain certificate. It independently checks validity and requires exactly one canonical `spiffe://` URI SAN.
- Authorization is exact identity plus exact HTTP method plus either an exact path or a terminal `/*` segment prefix. The default is deny.
- Ambiguous paths are rejected: backslashes, control bytes, repeated separators, dot segments, malformed encodings, and percent-encoded reserved bytes cannot reach policy matching. Only percent-encoded RFC 3986 unreserved characters are decoded before matching.
- Inbound `Forwarded`, `X-Forwarded-*`, and identity headers are discarded and reconstructed from the authenticated connection. Hop-by-hop and `Connection`-nominated headers are removed in both directions.
- `Via: 1.1 arkion-identity-proxy` is appended and an inbound copy of that marker returns `508 Loop Detected`.
- Audit logs contain only an allowlisted `Content-Type` and `User-Agent`, each stripped of controls and truncated to 256 characters. Authorization, cookies, credentials, bodies, certificate bytes, and URI queries are never logged.
- TLS private keys and generated test PKI are excluded from both Git and Docker build contexts.

The proxy inserts `X-Arkion-Client-Spiffe` for the upstream only after deleting any client-provided value. Upstreams must accept this header exclusively from the proxy's network identity.

## Build and test

Prerequisites are a current Rust toolchain, OpenSSL, curl, Python 3, and Docker.

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
docker build --pull -t identity-aware-tls-rev-proxy:local .
./scripts/container-smoke-test.sh identity-aware-tls-rev-proxy:local
```

The smoke test creates two disposable CAs and client identities, starts the included echo upstream, and checks:

- successful mTLS identity extraction, authorization, and method/path/query/body forwarding;
- `403` for a policy denial and rejection of missing, untrusted, expired, or not-yet-valid client certificates;
- application-layer rejection of missing, multiple, or non-canonical SPIFFE identities and a focused parser test for malformed certificate DER;
- overwrite of spoofed forwarding headers and removal of hop-by-hop headers;
- live trust rotation from CA v1 to CA v2 without restarting the container;
- continued service on the last known-good configuration plus failed readiness after a malformed update;
- recovery after restoring valid trust material;
- parseable JSON audit events with no authorization, cookie, hop-header, or body secrets.

Generated certificates are test-only. Positive-path certificates expire after seven days; negative fixtures use deliberately expired or future validity windows. Do not use them in production.

## Local run

Generate disposable TLS material and start any HTTP upstream on port 8080:

```bash
./scripts/generate-test-pki.sh .test-pki
cargo run --bin test-upstream
```

In another terminal, run the proxy directly:

```bash
LISTEN_ADDR=127.0.0.1:8443 \
UPSTREAM_URL=http://127.0.0.1:18080 \
TLS_CERT_PATH=.test-pki/server.crt \
TLS_KEY_PATH=.test-pki/server.key \
TLS_CLIENT_CA_PATH=.test-pki/client-ca.pem \
POLICY_PATH=examples/test-policy.json \
cargo run --bin identity-aware-tls-rev-proxy
```

Then call:

```bash
curl --cacert .test-pki/root-v1.crt \
  --cert .test-pki/client-v1.crt \
  --key .test-pki/client-v1.key \
  https://localhost:8443/readyz
```

Build and run the container with host networking on Linux:

```bash
docker build --pull -t identity-aware-tls-rev-proxy:local .
docker run --rm --network host \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/.test-pki:/config/tls:ro" \
  -v "$PWD/examples/test-policy.json:/config/policy.json:ro" \
  -e LISTEN_ADDR=127.0.0.1:8443 \
  -e UPSTREAM_URL=http://127.0.0.1:18080 \
  identity-aware-tls-rev-proxy:local
```

The local `--user` override lets the non-root process read the test key owned by the current user. In production, mount the key read-only with ownership and permissions for image UID/GID `10001:10001` instead.

## Configuration

| Environment variable | Default | Meaning |
|---|---:|---|
| `LISTEN_ADDR` | `0.0.0.0:8443` | HTTPS listener |
| `UPSTREAM_URL` | `http://backend:8080` | HTTP origin only; paths and queries are rejected |
| `TLS_CERT_PATH` | `/config/tls/server.crt` | PEM server certificate chain |
| `TLS_KEY_PATH` | `/config/tls/server.key` | PEM server private key |
| `TLS_CLIENT_CA_PATH` | `/config/tls/client-ca.pem` | PEM client trust anchors |
| `POLICY_PATH` | `/config/policy.json` | JSON authorization policy |
| `TRUST_RELOAD_INTERVAL_MS` | `2000` | TLS material polling interval |
| `TLS_HANDSHAKE_TIMEOUT_MS` | `5000` | Maximum TLS handshake time |
| `UPSTREAM_TIMEOUT_MS` | `5000` | Time to upstream response headers |
| `MAX_REQUEST_BODY_BYTES` | `1048576` | Buffered request-body limit |
| `MAX_IN_FLIGHT_REQUESTS` | `256` | Requests allowed through the proxy concurrently |
| `GRACEFUL_SHUTDOWN_TIMEOUT_SECS` | `10` | Connection drain deadline |
| `RUST_LOG` | crate at `info` | Service tracing filter; dependency traces remain disabled to prevent accidental header/body logging |

Configuration fails closed at startup. The upstream must be plain HTTP and cannot obviously point back to the listener. Production upstream TLS could be added with a separate server-auth trust configuration; silently reusing the client trust store would be unsafe.

## Authorization policy

The format is JSON so parsing can use `deny_unknown_fields` and fail on misspelled properties:

```json
{
  "policies": [
    {
      "identity": "spiffe://acme/prod/payment-agent",
      "allow": [
        {"method": "POST", "path": "/payments"}
      ]
    },
    {
      "identity": "spiffe://acme/prod/reporting-agent",
      "allow": [
        {"method": "GET", "path": "/reports/*"}
      ]
    }
  ]
}
```

`/reports/*` matches `/reports/` and descendants but not `/reports`, `/reports-evil`, or a path that becomes a different segment layout after decoding. Wildcards anywhere except a final `/*` are invalid. Duplicate rules, empty identities/rule sets, non-canonical methods, and malformed SPIFFE IDs fail startup. Policies contain only allow rules, so overlapping allowed prefixes cannot produce conflicting outcomes. Policy reload is deliberately not implemented; a production control plane should validate a versioned candidate and atomically swap it using the same last-known-good pattern as TLS material.

## TLS identity and trust rotation

### Why mTLS instead of server-only TLS?

Ordinary TLS encrypts traffic and lets the client authenticate the proxy, but it does not give the proxy a cryptographically verified client identity. Client authentication would therefore have to rely on an HTTP credential such as an API key or bearer token, which can be copied, replayed, forwarded accidentally, or exposed to application middleware and logs. This proxy is intended for non-human workloads, so mTLS was chosen to authenticate both sides during the TLS handshake and bind the caller identity to possession of a private key. Missing, expired, or untrusted client credentials are rejected before an HTTP request reaches the application, and a validated SPIFFE URI SAN supplies the identity used by policy and audit records.

mTLS adds certificate issuance, secure key delivery, trust-bundle rotation, and clock-synchronization requirements, so it is operationally more involved than server-only TLS. It is also authentication rather than authorization: a trusted certificate is still denied unless its canonical SPIFFE identity, HTTP method, and path match an explicit policy rule. Server-only TLS may be sufficient for interactive clients or systems with a separate identity-aware authentication layer; mTLS is appropriate here because the assignment targets service-to-service, non-human identities and requires rejection at the connection boundary.

Validation responsibilities are intentionally split:

| Layer | Responsibility |
|---|---|
| Rustls handshake | Require a certificate; build and cryptographically validate its chain to the active trust roots; validate time, signatures, key usage, and client-auth usage |
| Application connection setup | Parse the validated leaf and presented chain; extract subject, issuer, serial, validity, URI/DNS SANs; require exactly one canonical SPIFFE URI identity |
| HTTP middleware | Associate that immutable connection identity with each request and authorize method plus canonical path |

A missing, untrusted, expired, not-yet-valid, or cryptographically malformed certificate fails the TLS handshake. A chain that passes TLS but has a missing, multiple, or non-canonical SPIFFE identity is closed during application connection setup before any HTTP request is served.

The watcher reads the CA bundle, server certificate, and server key as one candidate snapshot. It fully parses the roots and verifies the server certificate/key pair before taking a short write lock to replace an `Arc<ServerConfig>`. An accept already in progress owns its old `Arc`; therefore existing TLS connections continue with their original trust decision, while connections accepted after the swap use the new roots. Rotate aggressively or drain old connections if revocation must take effect immediately.

A malformed or unreadable update never replaces the active configuration. The proxy continues serving with the last known-good configuration, logs a metadata-only rejection, and changes `/readyz` to `503` until a valid new or rolled-back snapshot is observed. Atomic file/directory replacement avoids partially projected Kubernetes Secret updates. Across a fleet, distribute a signed/versioned bundle in waves, watch readiness and the `tls_config_version`, retain the previous version, and roll back before advancing.

## Reverse-proxy behavior

- Method, encoded path, query, request body, response status/body, and end-to-end headers are preserved.
- Request bodies are buffered once and capped by `MAX_REQUEST_BODY_BYTES`; oversized bodies return `413`. Responses stream from the upstream without a proxy body-size limit.
- Audit latency ends when the response body completes or records `client_aborted`/`body_error`, so it includes upstream and downstream body transfer time.
- Incoming HTTP/1.1 and HTTP/2 are selected with ALPN. The current cleartext upstream connector uses HTTP/1.1 keep-alive. WebSocket/HTTP Upgrade tunneling is not supported because `Upgrade` is stripped.
- `Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` are regenerated rather than trusted. The original Host becomes the forwarded host; the upstream Host is set to the configured authority.
- No automatic retries are performed. Retrying a POST after an ambiguous disconnect can duplicate a payment or other side effect. A future retry policy should be limited to explicitly idempotent operations and use an end-to-end idempotency key.

## Resilience

The implementation includes more than the required three controls:

1. TLS handshake and upstream-response-header timeouts.
2. A bounded, buffered request body.
3. A fail-fast global concurrency semaphore returning `503` when saturated.
4. Graceful SIGINT/SIGTERM shutdown with a finite drain deadline.
5. mTLS-protected `/healthz` and `/readyz`; readiness detects a rejected TLS-material update.
6. Last-known-good trust material and rollback behavior.

The concurrency permit covers policy, request buffering, and the wait for upstream response headers. It is released when streaming begins, so a production deployment facing slow readers should also apply downstream idle/body-rate enforcement at its load balancer or extend the body wrapper to retain the permit.

## Audit records

Logs are newline-delimited JSON. An audit record resembles:

```json
{
  "fields": {
    "event": "http_audit",
    "request_id": "9c82...",
    "identity": "spiffe://acme/prod/payment-agent",
    "method": "POST",
    "path": "/payments",
    "decision": "ALLOW",
    "response_status": 200,
    "upstream_status": 200,
    "latency_ms": 14,
    "response_body_outcome": "complete"
  }
}
```

An incoming `X-Request-ID` is propagated only when it is 1–128 ASCII alphanumeric, dot, underscore, or hyphen characters; otherwise a UUID is generated. `upstream_status` is `0` when no upstream response was received. Query strings are forwarded but omitted from audit paths because they commonly contain secrets.

## Performance test

With the test upstream and proxy running and a policy that allows both benchmark paths:

```bash
python3 scripts/benchmark.py \
  --direct-url http://127.0.0.1:18080/echo \
  --proxy-url https://localhost:8443/echo \
  --ca .test-pki/root-v1.crt \
  --cert .test-pki/client-v1.crt \
  --key .test-pki/client-v1.key \
  --requests 1000 \
  --concurrency 1,10,100 \
  | tee benchmark-results/local.jsonl
```

The driver reports requests/second, p50, p95, p99, mean latency, error rate, and direct-to-proxy incremental latency. Each worker keeps one HTTP/1.1 connection and fully consumes responses. Primary overhead sources are the first-connection mTLS handshake and X.509 parsing, two HTTP protocol stacks, policy/path processing, header copying, bounded request buffering, structured auditing, and the additional proxy/upstream network hop. See [`benchmark-results/README.md`](benchmark-results/README.md) for recording requirements. Do not present numbers from a different machine or topology as production capacity.

### Local reference result

The following run was captured on 2026-10-19 from image `sha256:78cc5a15adf0688579d10f01349e968e5bc7fe18301cbc71c765b5575f6fc943`. Each target received 1,000 POST requests with a 24-byte body at each concurrency level; all requests succeeded.

| Concurrency | Direct req/s | Proxy req/s | Direct p50/p95/p99 (ms) | Proxy p50/p95/p99 (ms) | Incremental mean (ms) |
|---:|---:|---:|---:|---:|---:|
| 1 | 115.18 | 58.25 | 9.19 / 12.47 / 15.37 | 16.32 / 21.06 / 24.51 | 8.37 |
| 10 | 165.36 | 104.39 | 51.06 / 118.52 / 144.50 | 82.62 / 178.99 / 230.96 | 34.83 |
| 100 | 128.98 | 78.12 | 222.74 / 838.16 / 1207.54 | 455.13 / 1801.48 / 2981.27 | 325.06 |

This is a development-machine comparison, not a capacity claim. The direct upstream was a debug build on the host; the release proxy container, upstream, and Python thread-based load generator shared one Intel Core i7-2600K host (4 cores/8 threads, 15.6 GiB RAM) over loopback/host networking. The host ran Linux 6.12.113, Docker 26.1.5, Rust 1.99.1, and OpenSSL 3.5.7; the proxy image was built with Rust 1.85. Default proxy limits were used. TLS session resumption was not configured, and each worker's persistent connection therefore included one initial mTLS handshake. Audit events were written to Docker's log stream. Same-host CPU and logging contention dominate the high-concurrency tail, so production sizing requires a dedicated load generator, release-built upstream, representative network, and representative audit sink.

## Production considerations and limitations

- Terminate only on a protected network boundary, restrict upstream ingress to the proxy, and use a workload orchestrator or secret manager for key delivery and rotation.
- The strict SPIFFE parser intentionally supports a conservative ASCII subset and rejects percent-encoded path components. Use a standards-complete SPIFFE library if broader interoperability is required.
- Revocation via CRL/OCSP is not implemented. Prefer short-lived workload certificates and rapid trust-bundle rotation, or add a validated revocation source with explicit failure policy.
- Rate limiting and a circuit breaker are not included. Apply identity-aware distributed limits and per-upstream outlier detection when horizontally scaling.
- Trust material reloads dynamically; authorization policy and non-TLS environment configuration require restart.
- Upstream TLS, WebSocket upgrades, CONNECT tunneling, and HTTP/3 are outside this assignment's scope.
- Audit sinks need backpressure, retention, integrity protection, access controls, and field-level privacy review. Standard output is only the transport used here.
