#!/usr/bin/env bash
set -euo pipefail

image=${1:-identity-aware-tls-rev-proxy:local}
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
smoke_dir=$(mktemp -d)
container_name="identity-proxy-smoke-$$"
backend_pid=

cleanup() {
  local status=$?
  docker logs "$container_name" >"$smoke_dir/proxy.log" 2>&1 || true
  docker rm --force "$container_name" >/dev/null 2>&1 || true
  if [[ -n "$backend_pid" ]]; then
    kill "$backend_pid" >/dev/null 2>&1 || true
    wait "$backend_pid" >/dev/null 2>&1 || true
  fi
  if (( status != 0 )); then
    echo "proxy log after smoke-test failure:" >&2
    cat "$smoke_dir/proxy.log" >&2 || true
    echo "upstream log after smoke-test failure:" >&2
    cat "$smoke_dir/backend.log" >&2 || true
    if [[ -f "$smoke_dir/response.json" ]]; then
      echo "upstream response after smoke-test failure:" >&2
      cat "$smoke_dir/response.json" >&2 || true
    fi
  fi
  rm -rf "$smoke_dir"
}
trap cleanup EXIT

for command in cargo curl docker openssl python3; do
  command -v "$command" >/dev/null || {
    echo "required command not found: $command" >&2
    exit 2
  }
done

read -r backend_port proxy_port < <(python3 - <<'PY'
import socket
ports = []
for _ in range(2):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    ports.append(sock.getsockname()[1])
    sock.close()
print(*ports)
PY
)

"$repo_dir/scripts/generate-test-pki.sh" "$smoke_dir/pki" >/dev/null
cat >"$smoke_dir/policy.json" <<'JSON'
{
  "policies": [
    {
      "identity": "spiffe://acme/prod/smoke-client-v1",
      "allow": [
        {"method": "POST", "path": "/echo"}
      ]
    },
    {
      "identity": "spiffe://acme/prod/smoke-client-v2",
      "allow": [
        {"method": "POST", "path": "/echo"}
      ]
    }
  ]
}
JSON

cargo build --locked --bin test-upstream --manifest-path "$repo_dir/Cargo.toml" >/dev/null
TEST_UPSTREAM_ADDR="127.0.0.1:$backend_port" \
  "$repo_dir/target/debug/test-upstream" >"$smoke_dir/backend.log" 2>&1 &
backend_pid=$!

for _ in $(seq 1 50); do
  if curl --silent --fail --max-time 1 "http://127.0.0.1:$backend_port/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
kill -0 "$backend_pid" 2>/dev/null || {
  echo "test upstream failed to start" >&2
  cat "$smoke_dir/backend.log" >&2
  exit 1
}

docker run --detach \
  --name "$container_name" \
  --network host \
  --user "$(id -u):$(id -g)" \
  --volume "$smoke_dir/pki:/config/tls:ro" \
  --volume "$smoke_dir/policy.json:/config/policy.json:ro" \
  --env "LISTEN_ADDR=127.0.0.1:$proxy_port" \
  --env "UPSTREAM_URL=http://127.0.0.1:$backend_port" \
  --env TLS_CERT_PATH=/config/tls/server.crt \
  --env TLS_KEY_PATH=/config/tls/server.key \
  --env TLS_CLIENT_CA_PATH=/config/tls/client-ca.pem \
  --env POLICY_PATH=/config/policy.json \
  --env TRUST_RELOAD_INTERVAL_MS=100 \
  "$image" >/dev/null

curl_v1=(
  curl --silent --show-error --max-time 3
  --cacert "$smoke_dir/pki/root-v1.crt"
  --cert "$smoke_dir/pki/client-v1.crt"
  --key "$smoke_dir/pki/client-v1.key"
)
curl_v2=(
  curl --silent --show-error --max-time 3
  --cacert "$smoke_dir/pki/root-v1.crt"
  --cert "$smoke_dir/pki/client-v2.crt"
  --key "$smoke_dir/pki/client-v2.key"
)

ready=false
for _ in $(seq 1 80); do
  if "${curl_v1[@]}" --fail "https://localhost:$proxy_port/readyz" \
    >"$smoke_dir/ready.json" 2>"$smoke_dir/curl-error.log"; then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  cat "$smoke_dir/curl-error.log" >&2
  docker logs "$container_name" >&2
  exit 1
fi

status=$("${curl_v1[@]}" \
  --output "$smoke_dir/response.json" \
  --write-out '%{http_code}' \
  --request POST "https://localhost:$proxy_port/echo?mode=smoke" \
  --header 'content-type: text/plain' \
  --header 'authorization: Bearer smoke-authorization-secret' \
  --header 'cookie: session=smoke-cookie-secret' \
  --header 'x-forwarded-for: 203.0.113.9' \
  --data 'smoke request body')
[[ "$status" == 200 ]] || {
  echo "authorized request returned HTTP $status" >&2
  exit 1
}

python3 - "$smoke_dir/response.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["method"] == "POST"
assert value["path_and_query"] == "/echo?mode=smoke"
assert value["body"] == "smoke request body"
assert value["authorization_present"] is True
assert value["cookie_present"] is True
assert value["x_forwarded_for"] == "127.0.0.1"
assert value["x_forwarded_proto"] == "https"
assert value["identity"] == "spiffe://acme/prod/smoke-client-v1"
PY

# HTTP/2 forbids Connection, so exercise Connection-nominated removal over an
# explicit HTTP/1.1 ingress request while the request above covers h2-to-h1.
hop_status=$("${curl_v1[@]}" --http1.1 \
  --output "$smoke_dir/hop-response.json" \
  --write-out '%{http_code}' \
  --request POST "https://localhost:$proxy_port/echo" \
  --header 'connection: x-remove' \
  --header 'x-remove: smoke-hop-secret' \
  --data 'hop-header test')
[[ "$hop_status" == 200 ]] || {
  echo "hop-header request returned HTTP $hop_status" >&2
  exit 1
}
python3 - "$smoke_dir/hop-response.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
assert value["connection_nominated_header_present"] is False
PY

deny_status=$("${curl_v1[@]}" --output /dev/null --write-out '%{http_code}' \
  "https://localhost:$proxy_port/admin")
[[ "$deny_status" == 403 ]] || {
  echo "denied request returned HTTP $deny_status" >&2
  exit 1
}

if curl --silent --fail --max-time 2 \
  --cacert "$smoke_dir/pki/root-v1.crt" \
  "https://localhost:$proxy_port/readyz" >/dev/null 2>&1; then
  echo "request without a client certificate unexpectedly succeeded" >&2
  exit 1
fi

assert_client_rejected() {
  local name=$1
  local description=$2
  if curl --silent --fail --max-time 2 \
    --cacert "$smoke_dir/pki/root-v1.crt" \
    --cert "$smoke_dir/pki/$name.crt" \
    --key "$smoke_dir/pki/$name.key" \
    "https://localhost:$proxy_port/readyz" >/dev/null 2>&1; then
    echo "$description client certificate unexpectedly succeeded" >&2
    exit 1
  fi
}

assert_client_rejected client-expired expired
assert_client_rejected client-not-yet-valid not-yet-valid

# These certificates have valid chains, dates, and clientAuth usage, so Rustls
# accepts their TLS credentials. They are then rejected during application
# connection setup because the SPIFFE identity is absent, ambiguous, or
# non-canonical. /readyz bypasses policy, so policy denial cannot mask a failure.
for name in client-no-spiffe client-multiple-spiffe client-malformed-spiffe; do
  openssl verify \
    -CAfile "$smoke_dir/pki/root-v1.crt" \
    -purpose sslclient \
    "$smoke_dir/pki/$name.crt" >/dev/null
done
assert_client_rejected client-no-spiffe missing-SPIFFE
assert_client_rejected client-multiple-spiffe multiple-SPIFFE
assert_client_rejected client-malformed-spiffe non-canonical-SPIFFE

if "${curl_v2[@]}" --fail "https://localhost:$proxy_port/readyz" >/dev/null 2>&1; then
  echo "untrusted v2 client unexpectedly succeeded before rotation" >&2
  exit 1
fi

cp "$smoke_dir/pki/root-v2.crt" "$smoke_dir/pki/client-ca.pem.next"
mv "$smoke_dir/pki/client-ca.pem.next" "$smoke_dir/pki/client-ca.pem"
rotated=false
for _ in $(seq 1 50); do
  if "${curl_v2[@]}" --fail "https://localhost:$proxy_port/readyz" >/dev/null 2>&1; then
    rotated=true
    break
  fi
  sleep 0.1
done
[[ "$rotated" == true ]] || {
  echo "v2 trust bundle was not applied" >&2
  exit 1
}
if "${curl_v1[@]}" --fail "https://localhost:$proxy_port/readyz" >/dev/null 2>&1; then
  echo "v1 client remained trusted on a new connection after rotation" >&2
  exit 1
fi

printf '%s\n' 'not a certificate' >"$smoke_dir/pki/client-ca.pem.next"
mv "$smoke_dir/pki/client-ca.pem.next" "$smoke_dir/pki/client-ca.pem"
rejected=false
for _ in $(seq 1 50); do
  bad_status=$("${curl_v2[@]}" --output /dev/null --write-out '%{http_code}' \
    "https://localhost:$proxy_port/readyz")
  if [[ "$bad_status" == 503 ]]; then
    rejected=true
    break
  fi
  sleep 0.1
done
[[ "$rejected" == true ]] || {
  echo "bad trust update did not make readiness fail" >&2
  exit 1
}
cp "$smoke_dir/pki/root-v2.crt" "$smoke_dir/pki/client-ca.pem.next"
mv "$smoke_dir/pki/client-ca.pem.next" "$smoke_dir/pki/client-ca.pem"

recovered=false
for _ in $(seq 1 50); do
  if "${curl_v2[@]}" --fail "https://localhost:$proxy_port/readyz" >/dev/null 2>&1; then
    recovered=true
    break
  fi
  sleep 0.1
done
[[ "$recovered" == true ]] || {
  echo "trust-store rollback/recovery failed" >&2
  exit 1
}

docker logs "$container_name" >"$smoke_dir/proxy.log" 2>&1
python3 - "$smoke_dir/proxy.log" <<'PY'
import json, sys
lines = [line for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
events = [json.loads(line) for line in lines]
audits = [event for event in events if event.get("fields", {}).get("event") == "http_audit"]
assert audits, "no structured audit event found"
assert any(event["fields"].get("decision") == "ALLOW" for event in audits)
assert any(event["fields"].get("decision") == "DENY" for event in audits)
text = "\n".join(lines)
for secret in ["smoke-authorization-secret", "smoke-cookie-secret", "smoke-hop-secret", "smoke request body"]:
    assert secret not in text, f"secret leaked to logs: {secret}"
PY

echo "container smoke test: PASS"
