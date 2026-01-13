#!/bin/bash
# fossa-import-sbom.sh
# Quick SBOM import to FOSSA

set -e

# Configuration
FOSSA_TOKEN="${FOSSA_TOKEN}"
PROJECT_NAME="${1}"
VERSION="${2}"
SBOM_FILE="${3}"

# Validate inputs
if [ -z "$FOSSA_TOKEN" ]; then
  echo "Error: FOSSA_TOKEN environment variable not set"
  exit 1
fi

if [ -z "$PROJECT_NAME" ] || [ -z "$VERSION" ] || [ -z "$SBOM_FILE" ]; then
  echo "Usage: $0 <project_name> <version> <sbom_file>"
  echo "Example: $0 my-app v1.0.0 ./sbom.json"
  exit 1
fi

if [ ! -f "$SBOM_FILE" ]; then
  echo "Error: SBOM file not found: $SBOM_FILE"
  exit 1
fi

echo "======================================"
echo "FOSSA SBOM Import"
echo "======================================"
echo "Project: $PROJECT_NAME"
echo "Version: $VERSION"
echo "SBOM File: $SBOM_FILE"
echo "======================================"

# Step 1: Get signed URL
echo
echo "[1/2] Getting signed upload URL..."
RESPONSE=$(curl -s -G "https://app.fossa.com/api/components/signed_url" \
  --data-urlencode "packageSpec=custom+${PROJECT_NAME}" \
  --data-urlencode "revision=${VERSION}" \
  --data-urlencode "fetcherType=user_defined" \
  -H "Authorization: Bearer $FOSSA_TOKEN")

SIGNED_URL=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('signedURL', ''))")

if [ -z "$SIGNED_URL" ]; then
  echo "✗ Failed to get signed URL"
  echo "$RESPONSE"
  exit 1
fi

echo "✓ Signed URL obtained (valid for 5 minutes)"

# Step 2: Upload SBOM
echo
echo "[2/2] Uploading SBOM..."

# Detect content type
CONTENT_TYPE="application/json"
if [[ "$SBOM_FILE" == *.xml ]]; then
  CONTENT_TYPE="application/xml"
elif [[ "$SBOM_FILE" == *.spdx ]]; then
  CONTENT_TYPE="text/plain"
fi

HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -X PUT \
  -H "Content-Type: $CONTENT_TYPE" \
  --data-binary "@${SBOM_FILE}" \
  "$SIGNED_URL")

if [ "$HTTP_CODE" != "200" ]; then
  echo "✗ Upload failed (HTTP $HTTP_CODE)"
  exit 1
fi

echo "✓ SBOM uploaded successfully"

# Generate project URL
echo
echo "======================================"
echo "✓ SBOM Import Complete!"
echo "======================================"
PROJECT_URL="https://app.fossa.com/projects/custom%2B${PROJECT_NAME}/refs/branch/${VERSION}"
echo "View project at:"
echo "$PROJECT_URL"
echo
echo "FOSSA will now:"
echo "  • Parse SBOM components"
echo "  • Detect licenses"
echo "  • Scan for vulnerabilities"
echo "  • Check policy compliance"
echo
echo "Processing typically takes 1-5 minutes."
echo "======================================"
