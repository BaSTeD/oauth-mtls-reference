#!/bin/sh
# Generates a throwaway PKI for local development and tests:
#   root CA -> intermediate CA -> server certificates and client certificates,
#   plus the EC keys used for token signing and private_key_jwt.
#
# Nothing produced here is meant to leave your machine. The output directory
# is git-ignored.
#
# Usage: gen-certs.sh [output-dir]   (default: ./certs)
#   FORCE=1          regenerate even if the directory is already populated
#   EXTRA_SANS=...   additional subjectAltName entries for the server certs
set -eu

OUT="${1:-./certs}"
DAYS_CA=3650
DAYS_LEAF=90

if [ -f "$OUT/ca-chain.pem" ] && [ "${FORCE:-0}" != "1" ]; then
  echo "certificates already present in $OUT (set FORCE=1 to regenerate)"
  exit 0
fi

mkdir -p "$OUT/ca" "$OUT/server" "$OUT/client" "$OUT/keys"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

ec_key() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null
  chmod 600 "$1"
}

# --- root CA ---------------------------------------------------------------
ec_key "$OUT/ca/root.key"
openssl req -x509 -new -key "$OUT/ca/root.key" -sha256 -days "$DAYS_CA" \
  -subj "/O=oauth-mtls-reference/CN=Local Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$OUT/ca/root.crt"

# --- intermediate CA -------------------------------------------------------
ec_key "$OUT/ca/intermediate.key"
openssl req -new -key "$OUT/ca/intermediate.key" \
  -subj "/O=oauth-mtls-reference/CN=Local Test Issuing CA" \
  -out "$TMP/intermediate.csr"
cat > "$TMP/intermediate.ext" <<EXT
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EXT
openssl x509 -req -in "$TMP/intermediate.csr" -sha256 -days "$DAYS_CA" \
  -CA "$OUT/ca/root.crt" -CAkey "$OUT/ca/root.key" -CAcreateserial \
  -extfile "$TMP/intermediate.ext" -out "$OUT/ca/intermediate.crt" 2>/dev/null

cat "$OUT/ca/intermediate.crt" "$OUT/ca/root.crt" > "$OUT/ca-chain.pem"

# --- leaf certificates -----------------------------------------------------
# issue_leaf <dir> <name> <extendedKeyUsage> [subjectAltName]
issue_leaf() {
  dir="$1"; name="$2"; eku="$3"; san="${4:-}"
  ec_key "$OUT/$dir/$name.key"
  openssl req -new -key "$OUT/$dir/$name.key" \
    -subj "/O=oauth-mtls-reference/CN=$name" -out "$TMP/$name.csr"
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "keyUsage=critical,digitalSignature"
    echo "extendedKeyUsage=$eku"
    echo "subjectKeyIdentifier=hash"
    echo "authorityKeyIdentifier=keyid"
    [ -n "$san" ] && echo "subjectAltName=$san"
  } > "$TMP/$name.ext"
  openssl x509 -req -in "$TMP/$name.csr" -sha256 -days "$DAYS_LEAF" \
    -CA "$OUT/ca/intermediate.crt" -CAkey "$OUT/ca/intermediate.key" -CAcreateserial \
    -extfile "$TMP/$name.ext" -out "$TMP/$name.crt" 2>/dev/null
  # leaf first, then the issuing CA, so peers can build the chain
  cat "$TMP/$name.crt" "$OUT/ca/intermediate.crt" > "$OUT/$dir/$name.crt"
}

server_san() {
  san="DNS:$1,DNS:localhost,IP:127.0.0.1"
  [ -n "${EXTRA_SANS:-}" ] && san="$san,$EXTRA_SANS"
  echo "$san"
}

issue_leaf server auth-server serverAuth "$(server_san auth-server)"
issue_leaf server resource-server serverAuth "$(server_san resource-server)"
issue_leaf client demo-client clientAuth
# A second, perfectly valid client certificate from the same CA. It stands in
# for an attacker who stole an access token but not the legitimate client key.
issue_leaf client intruder clientAuth

# --- signing keys ----------------------------------------------------------
ec_key "$OUT/keys/as-signing.key"     # authorization server: signs tokens
ec_key "$OUT/keys/client-auth.key"    # client: signs private_key_jwt assertions
openssl pkey -in "$OUT/keys/client-auth.key" -pubout -out "$OUT/keys/client-auth.pub"

rm -f "$OUT/ca/"*.srl
echo "generated test PKI in $OUT"
