#!/bin/bash
# Generate self-signed SSL certificates for development

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}"

# Certificate configuration
DAYS=365
KEY_SIZE=2048
COUNTRY="US"
STATE="State"
LOCALITY="City"
ORG="IPAM System"
ORG_UNIT="IT"
COMMON_NAME="${COMMON_NAME:-ipam.local}"

echo "Generating self-signed SSL certificates..."
echo "Common Name: ${COMMON_NAME}"

# Generate private key
openssl genrsa -out "${CERT_DIR}/server.key" ${KEY_SIZE}

# Generate certificate signing request
openssl req -new \
    -key "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.csr" \
    -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORG}/OU=${ORG_UNIT}/CN=${COMMON_NAME}"

# Generate self-signed certificate
openssl x509 -req \
    -days ${DAYS} \
    -in "${CERT_DIR}/server.csr" \
    -signkey "${CERT_DIR}/server.key" \
    -out "${CERT_DIR}/server.crt" \
    -extfile <(printf "subjectAltName=DNS:${COMMON_NAME},DNS:localhost,IP:127.0.0.1")

# Set permissions
chmod 644 "${CERT_DIR}/server.crt"
chmod 600 "${CERT_DIR}/server.key"

# Clean up CSR
rm -f "${CERT_DIR}/server.csr"

echo ""
echo "Certificates generated successfully:"
echo "  - ${CERT_DIR}/server.crt"
echo "  - ${CERT_DIR}/server.key"
echo ""
echo "Note: These are self-signed certificates for development only."
echo "For production, use certificates from a trusted CA."
