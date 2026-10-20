#!/usr/bin/env bash
set -euo pipefail

pki_dir=${1:-.test-pki}
if [[ -z "$pki_dir" || "$pki_dir" == "/" ]]; then
  echo "refusing unsafe PKI output directory" >&2
  exit 2
fi

umask 077
mkdir -p "$pki_dir"

make_ca() {
  local name=$1
  openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out "$pki_dir/$name.key"
  openssl req -x509 -new -sha256 -days 30 \
    -key "$pki_dir/$name.key" \
    -subj "/CN=Arkion Test $name" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -out "$pki_dir/$name.crt"
}

sign_certificate() {
  local name=$1
  local ca=$2
  local subject=$3
  local extensions=$4

  openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out "$pki_dir/$name.key"
  openssl req -new -sha256 \
    -key "$pki_dir/$name.key" \
    -subj "$subject" \
    -out "$pki_dir/$name.csr"
  openssl x509 -req -sha256 -days 7 \
    -in "$pki_dir/$name.csr" \
    -CA "$pki_dir/$ca.crt" \
    -CAkey "$pki_dir/$ca.key" \
    -CAcreateserial \
    -extfile "$extensions" \
    -extensions extensions \
    -out "$pki_dir/$name.crt"
}

sign_certificate_with_dates() {
  local name=$1
  local ca=$2
  local subject=$3
  local extensions=$4
  local not_before=$5
  local not_after=$6

  openssl genpkey -algorithm EC \
    -pkeyopt ec_paramgen_curve:P-256 \
    -out "$pki_dir/$name.key"
  openssl req -new -sha256 \
    -key "$pki_dir/$name.key" \
    -subj "$subject" \
    -out "$pki_dir/$name.csr"
  openssl ca -batch -notext \
    -config "$ca_config" \
    -cert "$pki_dir/$ca.crt" \
    -keyfile "$pki_dir/$ca.key" \
    -in "$pki_dir/$name.csr" \
    -startdate "$not_before" \
    -enddate "$not_after" \
    -extfile "$extensions" \
    -extensions extensions \
    -out "$pki_dir/$name.crt"
}

make_ca root-v1
make_ca root-v2

server_extensions=$(mktemp)
client_v1_extensions=$(mktemp)
client_v2_extensions=$(mktemp)
client_no_spiffe_extensions=$(mktemp)
client_multiple_spiffe_extensions=$(mktemp)
client_malformed_spiffe_extensions=$(mktemp)
ca_state=$(mktemp -d)
ca_config="$ca_state/openssl-ca.cnf"
cleanup_extensions() {
  rm -f \
    "$server_extensions" \
    "$client_v1_extensions" \
    "$client_v2_extensions" \
    "$client_no_spiffe_extensions" \
    "$client_multiple_spiffe_extensions" \
    "$client_malformed_spiffe_extensions"
  rm -rf "$ca_state"
}
trap cleanup_extensions EXIT

mkdir "$ca_state/certs"
: >"$ca_state/index.txt"
printf '%s\n' '1000' >"$ca_state/serial"
cat >"$ca_config" <<EOF
[ca]
default_ca=ca_default

[ca_default]
database=$ca_state/index.txt
new_certs_dir=$ca_state/certs
serial=$ca_state/serial
default_md=sha256
default_days=7
policy=policy_any
unique_subject=no

[policy_any]
commonName=supplied
EOF

printf '%s\n' \
  '[extensions]' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature,keyEncipherment' \
  'extendedKeyUsage=serverAuth' \
  'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1' \
  >"$server_extensions"
printf '%s\n' \
  '[extensions]' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=clientAuth' \
  'subjectAltName=URI:spiffe://acme/prod/smoke-client-v1,DNS:smoke-client-v1' \
  >"$client_v1_extensions"
printf '%s\n' \
  '[extensions]' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=clientAuth' \
  'subjectAltName=URI:spiffe://acme/prod/smoke-client-v2,DNS:smoke-client-v2' \
  >"$client_v2_extensions"
printf '%s\n' \
  '[extensions]' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=clientAuth' \
  'subjectAltName=DNS:client-no-spiffe' \
  >"$client_no_spiffe_extensions"
printf '%s\n' \
  '[extensions]' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=clientAuth' \
  'subjectAltName=URI:spiffe://acme/prod/first,URI:spiffe://acme/prod/second' \
  >"$client_multiple_spiffe_extensions"
printf '%s\n' \
  '[extensions]' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=clientAuth' \
  'subjectAltName=URI:spiffe://ACME/prod/non-canonical' \
  >"$client_malformed_spiffe_extensions"

sign_certificate server root-v1 '/CN=localhost' "$server_extensions"
sign_certificate client-v1 root-v1 '/CN=smoke-client-v1' "$client_v1_extensions"
sign_certificate client-v2 root-v2 '/CN=smoke-client-v2' "$client_v2_extensions"
sign_certificate client-no-spiffe root-v1 '/CN=client-no-spiffe' "$client_no_spiffe_extensions"
sign_certificate client-multiple-spiffe root-v1 '/CN=client-multiple-spiffe' "$client_multiple_spiffe_extensions"
sign_certificate client-malformed-spiffe root-v1 '/CN=client-malformed-spiffe' "$client_malformed_spiffe_extensions"
sign_certificate_with_dates \
  client-expired root-v1 '/CN=client-expired' "$client_v1_extensions" \
  '20200101000000Z' '20200102000000Z'
sign_certificate_with_dates \
  client-not-yet-valid root-v1 '/CN=client-not-yet-valid' "$client_v1_extensions" \
  '20490101000000Z' '20490102000000Z'

cp "$pki_dir/root-v1.crt" "$pki_dir/client-ca.pem"
rm -f "$pki_dir"/*.csr "$pki_dir"/*.srl
chmod 600 "$pki_dir"/*.key
chmod 644 "$pki_dir"/*.crt "$pki_dir/client-ca.pem"
printf 'test PKI generated in %s\n' "$pki_dir"
