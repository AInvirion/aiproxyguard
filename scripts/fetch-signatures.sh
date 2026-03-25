#!/bin/bash
# Fetch and verify signatures from aiproxyguard-signatures releases
#
# This script:
# 1. Fetches the latest release from AInvirion/aiproxyguard-signatures
# 2. Downloads the free tier bundle
# 3. Verifies the Ed25519 signature
# 4. Extracts signatures to the signatures/ directory

set -euo pipefail

REPO="AInvirion/aiproxyguard-signatures"
PUBLIC_KEY="g9XbYVr5xQubfNlVwlhR1SLW5XMoILA9LzZiphkQpII="
SIGNATURES_DIR="${SIGNATURES_DIR:-signatures}"
TIER="${TIER:-free}"

echo "=== Fetching signatures from $REPO ==="

# Get latest release
echo "Fetching latest release..."
RELEASE_JSON=$(curl -sL "https://api.github.com/repos/$REPO/releases/latest")

if echo "$RELEASE_JSON" | grep -q '"message": "Not Found"'; then
    echo "ERROR: No releases found for $REPO"
    echo "Keeping existing signatures in $SIGNATURES_DIR"
    exit 0
fi

VERSION=$(echo "$RELEASE_JSON" | jq -r '.tag_name')
echo "Latest release: $VERSION"

# Find the free tier bundle asset
BUNDLE_NAME="${TIER}-${VERSION}.tar.gz"
BUNDLE_URL=$(echo "$RELEASE_JSON" | jq -r ".assets[] | select(.name == \"$BUNDLE_NAME\") | .browser_download_url")
SIG_URL=$(echo "$RELEASE_JSON" | jq -r ".assets[] | select(.name == \"${BUNDLE_NAME}.sig\") | .browser_download_url")

if [ -z "$BUNDLE_URL" ] || [ "$BUNDLE_URL" = "null" ]; then
    echo "ERROR: Bundle $BUNDLE_NAME not found in release"
    echo "Available assets:"
    echo "$RELEASE_JSON" | jq -r '.assets[].name'
    echo "Keeping existing signatures in $SIGNATURES_DIR"
    exit 0
fi

# Create temp directory
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Download bundle
echo "Downloading $BUNDLE_NAME..."
curl -sL "$BUNDLE_URL" -o "$TMPDIR/bundle.tar.gz"

# Download signature if available
if [ -n "$SIG_URL" ] && [ "$SIG_URL" != "null" ]; then
    echo "Downloading signature..."
    curl -sL "$SIG_URL" -o "$TMPDIR/bundle.sig"

    # Verify signature using Python (cryptography library)
    echo "Verifying signature..."
    python3 - "$TMPDIR/bundle.tar.gz" "$TMPDIR/bundle.sig" "$PUBLIC_KEY" << 'PYEOF'
import sys
import base64

bundle_path = sys.argv[1]
sig_path = sys.argv[2]
public_key_b64 = sys.argv[3]

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    with open(bundle_path, 'rb') as f:
        bundle_data = f.read()

    with open(sig_path, 'r') as f:
        signature_b64 = f.read().strip()

    public_key_bytes = base64.b64decode(public_key_b64)
    signature_bytes = base64.b64decode(signature_b64)

    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    public_key.verify(signature_bytes, bundle_data)

    print("Signature verified successfully!")
    sys.exit(0)
except Exception as e:
    print(f"Signature verification FAILED: {e}")
    sys.exit(1)
PYEOF

    if [ $? -ne 0 ]; then
        echo "ERROR: Signature verification failed!"
        exit 1
    fi
else
    echo "WARNING: No signature file found, skipping verification"
fi

# Extract bundle
echo "Extracting signatures to $SIGNATURES_DIR..."
mkdir -p "$SIGNATURES_DIR"

# Backup existing signatures
if [ -d "$SIGNATURES_DIR" ] && [ "$(ls -A $SIGNATURES_DIR 2>/dev/null)" ]; then
    echo "Backing up existing signatures..."
    mv "$SIGNATURES_DIR" "${SIGNATURES_DIR}.bak.$$"
    mkdir -p "$SIGNATURES_DIR"
fi

# Extract
tar -xzf "$TMPDIR/bundle.tar.gz" -C "$SIGNATURES_DIR"

# Count signatures
YAML_COUNT=$(find "$SIGNATURES_DIR" -name "*.yaml" -o -name "*.yml" | wc -l | tr -d ' ')
echo "Extracted $YAML_COUNT signature files"

# Create version marker
echo "$VERSION" > "$SIGNATURES_DIR/.version"
echo "$TIER" > "$SIGNATURES_DIR/.tier"

echo "=== Signatures updated to $VERSION ($TIER tier) ==="
