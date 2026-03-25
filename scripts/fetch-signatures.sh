#!/bin/bash
# Fetch and verify signatures from aiproxyguard-signatures releases
#
# This script:
# 1. Fetches the latest release from AInvirion/aiproxyguard-signatures
# 2. Downloads the free tier bundle
# 3. Verifies the Ed25519 signature
# 4. Extracts signatures to the signatures/ directory
#
# Requires: gh CLI (authenticated), jq, python3 with cryptography

set -euo pipefail

REPO="AInvirion/aiproxyguard-signatures"
PUBLIC_KEY="j4ztN19sQfU0pCqRV/GmlV50+oeqsO18mHQkMQnyb+k="
SIGNATURES_DIR="${SIGNATURES_DIR:-signatures}"
TIER="${TIER:-free}"

echo "=== Fetching signatures from $REPO ==="

# Check for gh CLI
if ! command -v gh &> /dev/null; then
    echo "ERROR: gh CLI not found. Install from https://cli.github.com/"
    exit 1
fi

# Get latest release tag
echo "Fetching latest release..."
VERSION=$(gh release view --repo "$REPO" --json tagName -q '.tagName' 2>/dev/null || echo "")

if [ -z "$VERSION" ]; then
    echo "ERROR: No releases found for $REPO"
    echo "Keeping existing signatures in $SIGNATURES_DIR"
    exit 0
fi

echo "Latest release: $VERSION"

# Create temp directory
TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

# Download bundle and signature using gh CLI
BUNDLE_NAME="${TIER}-${VERSION}.tar.gz"
echo "Downloading $BUNDLE_NAME..."

gh release download "$VERSION" \
    --repo "$REPO" \
    --pattern "$BUNDLE_NAME" \
    --pattern "${BUNDLE_NAME}.sig" \
    --dir "$TMPDIR" 2>/dev/null || {
    echo "ERROR: Failed to download $BUNDLE_NAME from release $VERSION"
    echo "Keeping existing signatures in $SIGNATURES_DIR"
    exit 0
}

# Check if files were downloaded
if [ ! -f "$TMPDIR/$BUNDLE_NAME" ]; then
    echo "ERROR: Bundle $BUNDLE_NAME not found in release"
    echo "Keeping existing signatures in $SIGNATURES_DIR"
    exit 0
fi

# Verify signature if available
if [ -f "$TMPDIR/${BUNDLE_NAME}.sig" ]; then
    echo "Verifying signature..."
    python3 - "$TMPDIR/$BUNDLE_NAME" "$TMPDIR/${BUNDLE_NAME}.sig" "$PUBLIC_KEY" << 'PYEOF'
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
    BACKUP_DIR="${SIGNATURES_DIR}.bak.$$"
    mv "$SIGNATURES_DIR" "$BACKUP_DIR"
    mkdir -p "$SIGNATURES_DIR"
fi

# Extract
tar -xzf "$TMPDIR/$BUNDLE_NAME" -C "$SIGNATURES_DIR"

# Count signatures
YAML_COUNT=$(find "$SIGNATURES_DIR" -name "*.yaml" -o -name "*.yml" 2>/dev/null | wc -l | tr -d ' ')
echo "Extracted $YAML_COUNT signature files"

# Create version marker
echo "$VERSION" > "$SIGNATURES_DIR/.version"
echo "$TIER" > "$SIGNATURES_DIR/.tier"

# Clean up backup if everything succeeded
if [ -n "${BACKUP_DIR:-}" ] && [ -d "$BACKUP_DIR" ]; then
    rm -rf "$BACKUP_DIR"
fi

echo "=== Signatures updated to $VERSION ($TIER tier) ==="
