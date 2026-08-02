#!/usr/bin/env sh
#
# Generates the PKI used by the RFC 8705 test stack:
#
#   ca.crt / ca.key           Certificate authority, trusted by Keycloak for client certs
#   keycloak.crt/.key         Keycloak server certificate (CN=keycloak)
#   client.crt/.key           Client certificate signed by the CA, for tls_client_auth
#   client-self-signed.crt    Self-signed client certificate, for self_signed_tls_client_auth
#   other-client.crt/.key     A second CA-signed certificate, to prove binding is enforced
#
set -eu

CERT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")/../certs" && pwd)"
cd "$CERT_DIR"

# The subject DN below must match the client's "Subject DN" in Keycloak (see realm-export.json).
CLIENT_SUBJECT="/CN=oidc-client-php"

if [ -f client.crt ] && [ "${FORCE:-0}" != "1" ]; then
  echo "Certificates already present in $CERT_DIR (set FORCE=1 to regenerate)"
  exit 0
fi

echo "Generating certificates in $CERT_DIR"

# --- Certificate authority -------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout ca.key -out ca.crt \
  -subj "/CN=OIDC Test CA" 2>/dev/null

# --- Keycloak server certificate -------------------------------------------
openssl req -newkey rsa:2048 -nodes \
  -keyout keycloak.key -out keycloak.csr \
  -subj "/CN=keycloak" 2>/dev/null

# SANs so the cert is valid both inside the compose network and from the host
cat > keycloak.ext <<'EOF'
subjectAltName = DNS:keycloak, DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in keycloak.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out keycloak.crt -days 3650 -extfile keycloak.ext 2>/dev/null

# --- CA-signed client certificate (tls_client_auth) ------------------------
openssl req -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr \
  -subj "$CLIENT_SUBJECT" 2>/dev/null

cat > client.ext <<'EOF'
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 3650 -extfile client.ext 2>/dev/null

# --- Self-signed client certificate (self_signed_tls_client_auth) ----------
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout client-self-signed.key -out client-self-signed.crt \
  -subj "/CN=oidc-client-php-self-signed" 2>/dev/null

# --- A different CA-signed client certificate ------------------------------
# Used to prove that a token bound to `client.crt` is rejected for this one.
openssl req -newkey rsa:2048 -nodes \
  -keyout other-client.key -out other-client.csr \
  -subj "/CN=other-client" 2>/dev/null

openssl x509 -req -in other-client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out other-client.crt -days 3650 -extfile client.ext 2>/dev/null

# Keycloak needs a truststore holding the CA to validate presented client certificates.
# It must be a Java trust store with a "trustedCertEntry" — a PKCS#12 file built by
# `openssl pkcs12 -export -nokeys` is a key store and makes Keycloak abort the handshake.
#
# The self-signed client certificate is added as well: with self_signed_tls_client_auth the
# certificate has no issuing CA, so the TLS layer can only accept it if it is trusted directly.
rm -f truststore.jks
docker run --rm -v "$CERT_DIR:/c" -w /c eclipse-temurin:21-jdk sh -c '
  keytool -importcert -noprompt -trustcacerts -alias ca \
    -file ca.crt -keystore truststore.jks -storepass password &&
  keytool -importcert -noprompt -trustcacerts -alias self-signed-client \
    -file client-self-signed.crt -keystore truststore.jks -storepass password
' >/dev/null 2>&1

rm -f ./*.csr ./*.ext ./*.srl
chmod 644 ./*.key ./*.crt
chmod 644 truststore.jks 2>/dev/null || true

echo "Client certificate SHA-256 thumbprint (base64url), as it appears in cnf/x5t#S256:"
openssl x509 -in client.crt -outform DER 2>/dev/null \
  | openssl dgst -sha256 -binary \
  | openssl base64 \
  | tr '+/' '-_' | tr -d '=\n'
echo ""
