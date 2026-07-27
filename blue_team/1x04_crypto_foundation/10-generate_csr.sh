#!/bin/bash

# ==========================================================
# Script: 10-generate_csr.sh
# Purpose: Generate OpenSSL config, private key and CSR
#          for MedDefense Health Systems
# ==========================================================

set -e

KEY_DIR="./private"
CSR_DIR="./csr"

CONFIG_FILE="./openssl-san.cnf"
KEY_FILE="$KEY_DIR/portal_key.pem"
CSR_FILE="$CSR_DIR/portal.csr"

echo "=== MedDefense CSR Generation ==="

if ! command -v openssl >/dev/null 2>&1; then
    echo "Error: OpenSSL is not installed."
    exit 1
fi

echo "[OK] OpenSSL available."

mkdir -p "$KEY_DIR"
mkdir -p "$CSR_DIR"

chmod 700 "$KEY_DIR"

echo "[OK] Directories created."

echo "Creating OpenSSL configuration file..."

cat > "$CONFIG_FILE" <<EOF
[ req ]
default_bits       = 2048
default_md         = sha256
prompt             = no
distinguished_name = req_dn
req_extensions     = req_ext

[ req_dn ]
C  = US
ST = New York
L  = New York
O  = MedDefense Health Systems
OU = Information Technology
CN = portal.meddefense.local
emailAddress = meddefense.it@mail.com

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = portal.meddefense.local
DNS.2 = login.meddefense.local
DNS.3 = patient.meddefense.local
EOF

echo "[OK] Configuration file created:"
echo "     $CONFIG_FILE"

echo "Generating RSA 2048-bit private key..."

openssl genrsa \
    -out "$KEY_FILE" \
    2048

chmod 600 "$KEY_FILE"

echo "[OK] Private key created:"
echo "     $KEY_FILE"

echo "Generating CSR..."

openssl req \
    -new \
    -key "$KEY_FILE" \
    -out "$CSR_FILE" \
    -config "$CONFIG_FILE"

echo "[OK] CSR created:"
echo "     $CSR_FILE"

echo
echo "Verifying CSR..."

openssl req \
    -in "$CSR_FILE" \
    -noout \
    -text

echo
echo "=== Completed Successfully ==="
echo
echo "Generated files:"
echo " - OpenSSL config: $CONFIG_FILE"
echo " - Private key:   $KEY_FILE"
echo " - CSR:           $CSR_FILE"
