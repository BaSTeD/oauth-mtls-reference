#!/bin/sh
# Rotates the demo client's TLS certificate: issues a new key pair and
# certificate from the intermediate CA and keeps the previous pair next to it
# as demo-client.previous.{crt,key}.
#
# Access tokens issued before the rotation stay bound to the old certificate
# (cnf.x5t#S256), so they stop working as soon as the client presents the new
# one. The client simply requests a new token.
#
# Usage: rotate-client.sh [cert-dir]   (default: ./certs)
set -eu

OUT="${1:-./certs}"
NAME=demo-client
DAYS_LEAF=90

[ -f "$OUT/ca/intermediate.key" ] || { echo "no PKI found in $OUT, run gen-certs.sh first" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mv "$OUT/client/$NAME.crt" "$OUT/client/$NAME.previous.crt"
mv "$OUT/client/$NAME.key" "$OUT/client/$NAME.previous.key"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUT/client/$NAME.key" 2>/dev/null
chmod 600 "$OUT/client/$NAME.key"
openssl req -new -key "$OUT/client/$NAME.key" \
  -subj "/O=oauth-mtls-reference/CN=$NAME" -out "$TMP/$NAME.csr"
cat > "$TMP/$NAME.ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EXT
openssl x509 -req -in "$TMP/$NAME.csr" -sha256 -days "$DAYS_LEAF" \
  -CA "$OUT/ca/intermediate.crt" -CAkey "$OUT/ca/intermediate.key" -CAcreateserial \
  -extfile "$TMP/$NAME.ext" -out "$TMP/$NAME.crt" 2>/dev/null
cat "$TMP/$NAME.crt" "$OUT/ca/intermediate.crt" > "$OUT/client/$NAME.crt"
rm -f "$OUT/ca/"*.srl

echo "rotated $NAME certificate, previous pair kept as $NAME.previous.{crt,key}"
