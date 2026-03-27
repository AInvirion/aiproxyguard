# Encrypted Signature Bundles Implementation Plan

## Problem Statement

### Current Vulnerabilities
1. **Unauthorized Access**: A free-tier user could reverse-engineer the API and attempt to download pro/enterprise signature bundles
2. **License Piracy**: A user could subscribe for one month, download signatures, cancel subscription, and continue using them indefinitely (or redistribute them)

### Current State
- ML models: Encrypted with AES-256-GCM, time-bonded via license with `expires_at`
- Signatures: Plain YAML, only manifest is signed (prevents tampering but not piracy)

## Proposed Solution

Encrypt signature bundles using envelope encryption (same pattern as ML models):

```
Cloud encrypts bundle once with Bundle-DEK (cached)
     ↓
License wraps Bundle-DEK for specific account + expiration
     ↓
Proxy unwraps DEK from license, decrypts bundle
     ↓
Parse YAML → SignatureBundle (with expiration) → In-memory
```

## Architecture

### Envelope Encryption Scheme

Unlike naive "unique DEK per license" (which would require re-encrypting bundles for every request), we use envelope encryption:

```
┌─────────────────────────────────────────────────────────────┐
│                     Cloud (one-time)                        │
│  1. Generate Bundle-DEK (random AES-256 key)                │
│  2. Encrypt bundle YAML with Bundle-DEK → Ciphertext        │
│  3. Store ciphertext (static, cached on CDN)                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Cloud (per license request)                  │
│  1. Verify account tier + active subscription                │
│  2. Wrap Bundle-DEK for this account:                        │
│     - Add expires_at (30 days)                               │
│     - Sign with Ed25519                                      │
│  3. Return license containing wrapped DEK                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         Proxy                                │
│  1. Verify license signature                                 │
│  2. Check expires_at                                         │
│  3. Extract DEK from license                                 │
│  4. Download encrypted bundle (static URL)                   │
│  5. Decrypt with DEK                                         │
│  6. Parse YAML → SignatureBundle with expiration             │
└─────────────────────────────────────────────────────────────┘
```

### License Structure
```json
{
  "license_id": "lic_abc123",
  "license_type": "signature_bundle",
  "bundle_id": "sig-enterprise-v1",
  "bundle_version": "2024.03.26",
  "account_id": "acc_xyz",
  "tier": "enterprise",
  "dek": "<base64-encoded-AES-256-key>",
  "issued_at": "2024-03-26T00:00:00Z",
  "expires_at": "2024-04-26T00:00:00Z",
  "signature": "<ed25519-signature>"
}
```

### Encrypted Bundle Format
```
[4 bytes: header length][JSON header][AES-256-GCM ciphertext]

Header:
{
  "format": "aiproxyguard-encrypted-bundle-v1",
  "bundle_id": "sig-enterprise-v1",
  "version": "2024.03.26",
  "nonce": "<base64>",
  "sha256_plaintext": "<hash>"
}
```

### New Data Model: SignatureBundle

Current `SignatureSet` lacks bundle-level metadata. We need a new structure:

```python
@dataclass
class SignatureBundle:
    """A bundle of signatures with licensing metadata."""
    bundle_id: str
    version: str
    tier: str  # "free", "pro", "enterprise"
    expires_at: datetime | None  # None for free tier (never expires)
    signatures: SignatureSet

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_free(self) -> bool:
        return self.tier == "free"
```

The scanner pipeline will work with multiple bundles:

```python
@dataclass
class SignatureBundleSet:
    """Collection of signature bundles with expiration tracking."""
    bundles: list[SignatureBundle]

    def get_active_signatures(self) -> SignatureSet:
        """Return only non-expired signatures."""
        active = []
        for bundle in self.bundles:
            if not bundle.is_expired:
                active.extend(bundle.signatures.signatures)
            else:
                logger.warning(f"Bundle {bundle.bundle_id} expired, skipping")
        return SignatureSet(signatures=active)
```

## API Flow

### 1. Manifest Request (unchanged)
```
GET /v1/signatures/manifest
Authorization: Bearer {api_key}

Response:
{
  "version": "2024.03.26",
  "bundles": [
    {"id": "sig-free-v1", "tier": "free", "encrypted": false},
    {"id": "sig-pro-v1", "tier": "pro", "encrypted": true},
    {"id": "sig-enterprise-v1", "tier": "enterprise", "encrypted": true}
  ],
  "sequence": 42,
  "signature": "<manifest-signature>"
}
```

### 2. License Request (for encrypted bundles)
```
POST /v1/signatures/bundles/{bundle_id}/license
Authorization: Bearer {api_key}

Response:
{
  "license_id": "lic_abc123",
  "license_type": "signature_bundle",
  "bundle_id": "sig-enterprise-v1",
  "bundle_version": "2024.03.26",
  "dek": "<base64-AES-key>",
  "expires_at": "2024-04-26T00:00:00Z",
  "download_url": "https://cdn.../sig-enterprise-v1.enc",
  "signature": "<ed25519-signature>"
}
```

### 3. Bundle Download
```
GET {download_url}
→ Raw encrypted bytes (static, CDN-cacheable)
```

### 4. Free Bundles (unchanged)
```
GET /v1/signatures/bundles/{bundle_id}/content
→ Plain YAML (no encryption)
```

## Implementation Details

### Proxy Side Changes

#### 1. Generalize `license.py` (NO new file)

Instead of creating duplicate `bundle_license.py`, generalize existing `src/aiproxyguard/scanner/ml/license.py`:

```python
# Rename/move to: src/aiproxyguard/crypto/license.py

@dataclass
class License:
    """Generic license for encrypted content (models or bundles)."""
    license_id: str
    license_type: str  # "ml_model" or "signature_bundle"
    resource_id: str   # model_id or bundle_id
    resource_version: str
    account_id: str
    tier: str
    dek: bytes
    issued_at: datetime
    expires_at: datetime
    signature: str
    download_url: str | None = None


def parse_license(license_data: dict) -> License:
    """Parse license from API response (works for both ML and signatures)."""
    ...

def verify_license_signature(license_data: dict, public_key_b64: str) -> bool:
    """Verify Ed25519 signature on license."""
    ...

def is_license_valid(license: License, public_key_b64: str, license_data: dict) -> tuple[bool, str]:
    """Check signature + expiration."""
    ...

def decrypt_content(encrypted_data: bytes, dek: bytes, expected_format: str) -> bytes:
    """Decrypt AES-256-GCM content (works for models or bundles)."""
    # expected_format: "aiproxyguard-encrypted-model-v1" or "aiproxyguard-encrypted-bundle-v1"
    ...
```

#### 2. New file: `src/aiproxyguard/signatures/bundle.py`

```python
"""Signature bundle with licensing metadata."""

from dataclasses import dataclass
from datetime import datetime, timezone

from aiproxyguard.signatures.models import SignatureSet


@dataclass
class SignatureBundle:
    bundle_id: str
    version: str
    tier: str
    expires_at: datetime | None
    signatures: SignatureSet

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at


@dataclass
class SignatureBundleSet:
    bundles: list[SignatureBundle]

    def get_active_signatures(self) -> SignatureSet:
        """Merge non-expired bundles into single SignatureSet."""
        ...

    def get_earliest_expiration(self) -> datetime | None:
        """For scheduling re-sync before expiration."""
        ...
```

#### 3. Modify: `src/aiproxyguard/signatures/loader.py`

```python
def parse_signatures_from_bundles(
    bundle_contents: list[dict],
    licenses: dict[str, License] | None = None,  # bundle_id -> License
) -> SignatureBundleSet:
    """Parse bundles into SignatureBundleSet with expiration tracking."""
    bundles = []
    for bundle_data in bundle_contents:
        bundle_id = bundle_data.get("bundle_id")
        content = bundle_data.get("content")  # Already decrypted YAML

        # Get expiration from license if available
        license = licenses.get(bundle_id) if licenses else None
        expires_at = license.expires_at if license else None

        signatures = _parse_yaml_signatures(content)
        bundles.append(SignatureBundle(
            bundle_id=bundle_id,
            version=bundle_data.get("version", ""),
            tier=bundle_data.get("tier", "free"),
            expires_at=expires_at,
            signatures=signatures,
        ))

    return SignatureBundleSet(bundles=bundles)
```

#### 4. Modify: `src/aiproxyguard/control_plane.py`

```python
class ControlPlaneClient:
    def __init__(self, ...):
        ...
        self._bundle_licenses: dict[str, dict] = {}  # bundle_id -> license_data
        self._bundle_set: SignatureBundleSet | None = None

    async def _request_bundle_license(self, bundle_id: str) -> dict | None:
        """Request license for encrypted bundle."""
        response = await self.client.post(
            f"/v1/signatures/bundles/{bundle_id}/license"
        )
        response.raise_for_status()
        return response.json()

    async def _fetch_encrypted_bundle(self, download_url: str) -> bytes:
        """Download encrypted bundle bytes."""
        response = await self.client.get(download_url)
        response.raise_for_status()
        return response.content

    async def _fetch_and_apply_signatures(self) -> None:
        """Sync signatures with encryption support and offline fallback."""
        from aiproxyguard.signatures.cache import (
            load_bundle_cache, save_bundle_cache, clear_expired_cache
        )

        bundle_contents = []
        licenses = {}

        # 1. Try to fetch manifest from cloud
        try:
            manifest = await self._fetch_manifest()
            # Verify manifest signature (existing)
            ...
        except Exception as e:
            logger.warning(f"Failed to fetch manifest: {e}, trying offline cache")
            # Fall back to cached bundles (offline mode)
            await self._load_from_cache()
            return

        # 2. For each bundle, fetch content (with cache fallback)
        for bundle_info in manifest["bundles"]:
            bundle_id = bundle_info["id"]
            is_encrypted = bundle_info.get("encrypted", False)

            if is_encrypted:
                bundle_data = await self._fetch_encrypted_bundle_with_fallback(
                    bundle_id, bundle_info
                )
                if bundle_data:
                    bundle_contents.append(bundle_data["content_info"])
                    if bundle_data.get("license"):
                        licenses[bundle_id] = bundle_data["license"]
            else:
                # Plain bundle (free tier)
                content = await self._fetch_plain_bundle(bundle_id)
                bundle_contents.append({
                    "bundle_id": bundle_id,
                    "version": bundle_info.get("version"),
                    "tier": "free",
                    "content": content,
                })

        # 3. Parse into SignatureBundleSet
        self._bundle_set = parse_signatures_from_bundles(bundle_contents, licenses)
        self._bundle_licenses = {b: l for b, l in licenses.items()}

        # 4. Notify callback
        if self._signature_callback:
            self._signature_callback(self._bundle_set.get_active_signatures())

    async def _fetch_encrypted_bundle_with_fallback(
        self, bundle_id: str, bundle_info: dict
    ) -> dict | None:
        """Fetch encrypted bundle from cloud, fall back to cache on failure."""
        from aiproxyguard.signatures.cache import load_bundle_cache, save_bundle_cache

        try:
            # Try to get fresh license from cloud
            license_data = await self._request_bundle_license(bundle_id)
            if not license_data:
                raise Exception("No license returned")

            # Verify license
            license = parse_license(license_data)
            valid, reason = is_license_valid(license, PUBLIC_KEY, license_data)
            if not valid:
                raise Exception(f"Invalid license: {reason}")

            # Download encrypted content
            encrypted_bytes = await self._fetch_encrypted_bundle(
                license_data["download_url"]
            )

            # Decrypt
            decrypted = decrypt_content(
                encrypted_bytes,
                license.dek,
                "aiproxyguard-encrypted-bundle-v1"
            )

            # Cache for offline use
            save_bundle_cache(bundle_id, encrypted_bytes, license_data)

            return {
                "license": license,
                "content_info": {
                    "bundle_id": bundle_id,
                    "version": bundle_info.get("version"),
                    "tier": bundle_info.get("tier"),
                    "content": decrypted.decode("utf-8"),
                }
            }

        except Exception as e:
            logger.warning(f"Failed to fetch {bundle_id} from cloud: {e}")

            # Try cache fallback
            cached = load_bundle_cache(bundle_id)
            if cached:
                encrypted_bytes, license_data = cached
                license = parse_license(license_data)

                decrypted = decrypt_content(
                    encrypted_bytes,
                    license.dek,
                    "aiproxyguard-encrypted-bundle-v1"
                )

                logger.info(f"Loaded {bundle_id} from cache (expires {license.expires_at})")
                return {
                    "license": license,
                    "content_info": {
                        "bundle_id": bundle_id,
                        "version": license_data.get("bundle_version"),
                        "tier": bundle_info.get("tier"),
                        "content": decrypted.decode("utf-8"),
                    }
                }

            logger.error(f"No cache available for {bundle_id}")
            return None

    async def _load_from_cache(self) -> None:
        """Load all bundles from cache (offline mode)."""
        from aiproxyguard.signatures.cache import CACHE_DIR, load_bundle_cache

        bundle_contents = []
        licenses = {}

        if not CACHE_DIR.exists():
            logger.warning("No cache directory, starting with empty signatures")
            return

        for bundle_path in CACHE_DIR.iterdir():
            if not bundle_path.is_dir():
                continue

            bundle_id = bundle_path.name
            cached = load_bundle_cache(bundle_id)

            if cached:
                encrypted_bytes, license_data = cached
                license = parse_license(license_data)

                try:
                    decrypted = decrypt_content(
                        encrypted_bytes,
                        license.dek,
                        "aiproxyguard-encrypted-bundle-v1"
                    )
                    bundle_contents.append({
                        "bundle_id": bundle_id,
                        "version": license_data.get("bundle_version"),
                        "tier": license_data.get("tier", "unknown"),
                        "content": decrypted.decode("utf-8"),
                    })
                    licenses[bundle_id] = license
                    logger.info(f"Loaded {bundle_id} from cache")
                except Exception as e:
                    logger.error(f"Failed to decrypt cached {bundle_id}: {e}")

        self._bundle_set = parse_signatures_from_bundles(bundle_contents, licenses)
        self._bundle_licenses = {b: l for b, l in licenses.items()}

        if self._signature_callback:
            self._signature_callback(self._bundle_set.get_active_signatures())

        logger.info(f"Offline mode: loaded {len(bundle_contents)} bundles from cache")

    # ... existing callback code ...
        if self._signature_callback:
            self._signature_callback(self._bundle_set.get_active_signatures())
```

#### 5. Modify: `src/aiproxyguard/scanner/pipeline.py`

```python
class ScannerPipeline:
    def __init__(self, config, bundle_set: SignatureBundleSet, ...):
        self._bundle_set = bundle_set
        self._rebuild_scanner()

    def _rebuild_scanner(self):
        """Rebuild regex scanner with active (non-expired) signatures."""
        active_sigs = self._bundle_set.get_active_signatures()
        self._regex_scanner = RegexScanner(active_sigs)

    def reload_signatures(self, bundle_set: SignatureBundleSet):
        """Called when new signatures synced."""
        self._bundle_set = bundle_set
        self._rebuild_scanner()

    def scan(self, text: str) -> ScanResult:
        # Check for expired bundles and warn
        for bundle in self._bundle_set.bundles:
            if bundle.is_expired and not bundle.is_free:
                logger.warning(
                    f"Bundle {bundle.bundle_id} expired at {bundle.expires_at}"
                )

        # Scan with active signatures only
        return self._regex_scanner.scan(text)
```

#### 6. Persistence for Offline Support

New file: `src/aiproxyguard/signatures/cache.py`

```python
"""Local cache for encrypted bundles and licenses."""

import json
import logging
from pathlib import Path
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
CACHE_DIR = Path("/var/lib/aiproxyguard/cache")  # or ~/.aiproxyguard/cache


def save_bundle_cache(
    bundle_id: str,
    encrypted_bytes: bytes,
    license_data: dict,
) -> None:
    """Persist encrypted bundle + license for offline use."""
    cache_path = CACHE_DIR / bundle_id
    cache_path.mkdir(parents=True, exist_ok=True)

    (cache_path / "bundle.enc").write_bytes(encrypted_bytes)
    (cache_path / "license.json").write_text(json.dumps(license_data))


def load_bundle_cache(bundle_id: str) -> tuple[bytes, dict] | None:
    """Load cached bundle + license if available and not expired."""
    cache_path = CACHE_DIR / bundle_id
    if not cache_path.exists():
        return None

    encrypted = (cache_path / "bundle.enc").read_bytes()
    license_data = json.loads((cache_path / "license.json").read_text())

    # Check if license still valid
    expires_at = datetime.fromisoformat(license_data["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        logger.info(f"Cached license for {bundle_id} expired")
        return None

    return encrypted, license_data


def clear_expired_cache() -> None:
    """Remove expired cached bundles."""
    ...
```

### Cloud Side Changes (aiproxyguard-cloud)

#### 1. Bundle Encryption Service

```python
# server/app/services/bundle_encryption.py

class BundleEncryptionService:
    def __init__(self):
        self._bundle_keys: dict[str, bytes] = {}  # bundle_id -> DEK (in-memory or KMS)

    def encrypt_bundle(self, bundle_id: str, version: str, yaml_content: str) -> tuple[bytes, bytes]:
        """Encrypt bundle, return (ciphertext, dek)."""
        # Generate or retrieve DEK for this bundle
        if bundle_id not in self._bundle_keys:
            self._bundle_keys[bundle_id] = os.urandom(32)  # AES-256

        dek = self._bundle_keys[bundle_id]
        nonce = os.urandom(12)

        # Encrypt
        aesgcm = AESGCM(dek)
        aad = f"{bundle_id}:{version}".encode()
        ciphertext = aesgcm.encrypt(nonce, yaml_content.encode(), aad)

        # Build header
        header = {
            "format": "aiproxyguard-encrypted-bundle-v1",
            "bundle_id": bundle_id,
            "version": version,
            "nonce": base64.b64encode(nonce).decode(),
            "sha256_plaintext": hashlib.sha256(yaml_content.encode()).hexdigest(),
        }

        # Package
        header_bytes = json.dumps(header).encode()
        result = len(header_bytes).to_bytes(4, "big") + header_bytes + ciphertext

        return result, dek

    def issue_license(
        self,
        bundle_id: str,
        account_id: str,
        tier: str,
        duration_days: int = 30,
    ) -> dict:
        """Issue license wrapping the bundle DEK."""
        dek = self._bundle_keys.get(bundle_id)
        if not dek:
            raise ValueError(f"Bundle {bundle_id} not encrypted")

        now = datetime.now(timezone.utc)
        license_data = {
            "license_id": f"lic_{uuid4().hex[:12]}",
            "license_type": "signature_bundle",
            "bundle_id": bundle_id,
            "bundle_version": self._get_bundle_version(bundle_id),
            "account_id": account_id,
            "tier": tier,
            "dek": base64.b64encode(dek).decode(),
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(days=duration_days)).isoformat(),
            "download_url": f"https://cdn.aiproxyguard.com/bundles/{bundle_id}.enc",
        }

        # Sign
        license_data["signature"] = self._sign_license(license_data)

        return license_data
```

#### 2. New Endpoint: License Request

```python
# server/app/api/v1/signatures.py

@router.post("/bundles/{bundle_id}/license")
async def request_bundle_license(
    bundle_id: str,
    current_account: Account = Depends(get_current_account),
    encryption_service: BundleEncryptionService = Depends(),
):
    # Verify account has access
    bundle = await get_bundle(bundle_id)
    if not account_has_tier_access(current_account, bundle.tier):
        raise HTTPException(403, "Upgrade required")

    # Verify subscription active
    if not current_account.subscription_active:
        raise HTTPException(403, "Subscription inactive")

    # Issue license
    license_data = encryption_service.issue_license(
        bundle_id=bundle_id,
        account_id=current_account.id,
        tier=bundle.tier,
    )

    return license_data
```

#### 3. Modify Content Endpoint

```python
@router.get("/bundles/{bundle_id}/content")
async def get_bundle_content(
    bundle_id: str,
    current_account: Account = Depends(get_current_account),
):
    bundle = await get_bundle(bundle_id)

    if bundle.tier == "free":
        # Return plain YAML
        return Response(content=bundle.content, media_type="text/yaml")
    else:
        # Encrypted bundles require license first
        raise HTTPException(
            400,
            "Encrypted bundle - use POST /bundles/{id}/license first"
        )
```

## Security Considerations

1. **Envelope encryption**: Bundle encrypted once, DEK wrapped per-license
2. **DEK isolation**: Each bundle has unique DEK; compromise of one doesn't affect others
3. **Short expiration**: 30-day licenses force periodic renewal
4. **Subscription check on renewal**: Lapsed subscriptions can't renew
5. **Signed licenses**: Ed25519 prevents tampering with expiration
6. **Bundle hash verification**: SHA-256 integrity check after decryption
7. **Offline cache encrypted**: Cached bundles remain encrypted on disk

## Performance Impact

| Operation | When | Latency |
|-----------|------|---------|
| License request | Startup + every 30 days | ~100ms network |
| Bundle download | Startup + on new version | ~200ms (CDN) |
| Bundle decryption | Startup + on new version | ~1-2ms for 100KB |
| Expiration check | Per scan | ~1ns (memory compare) |
| Regex scanning | Every request | Unchanged |

**Net impact on request latency: Zero** (all crypto at startup/sync time)

## Offline / Library Support

This design supports offline usage:

```python
from aiproxyguard import Scanner

# First run: fetches license + encrypted bundles, caches locally
scanner = Scanner(api_key="apg_xxx")

# Subsequent runs (even offline): loads from cache if license valid
scanner = Scanner(api_key="apg_xxx")  # Works offline for 30 days

# After 30 days without network: license expired
scanner = Scanner(api_key="apg_xxx")  # Falls back to free signatures only
```

Cache location:
- Docker: `/var/lib/aiproxyguard/cache/`
- Library: `~/.aiproxyguard/cache/`

## Migration Plan

### Phase 1: Implement (backwards compatible)
- Cloud serves both encrypted (new) and plain (legacy) for paid bundles
- Manifest includes `"encrypted": true/false` flag
- Proxy detects format and handles accordingly
- Free bundles remain unencrypted

### Phase 2: Deprecate plain format
- Log warnings when serving plain format for paid bundles
- Set sunset date (e.g., 60 days)

### Phase 3: Remove plain format
- Paid bundles only served encrypted
- Free bundles remain plain

## Files to Modify

### Proxy (aiproxyguard)
- [ ] `src/aiproxyguard/crypto/__init__.py` (new module)
- [ ] `src/aiproxyguard/crypto/license.py` (move + generalize from scanner/ml/license.py)
- [ ] `src/aiproxyguard/signatures/bundle.py` (new - SignatureBundle, SignatureBundleSet)
- [ ] `src/aiproxyguard/signatures/cache.py` (new - persistence)
- [ ] `src/aiproxyguard/signatures/loader.py` (modify - return SignatureBundleSet)
- [ ] `src/aiproxyguard/signatures/models.py` (keep as-is, bundle.py wraps it)
- [ ] `src/aiproxyguard/control_plane.py` (modify - encrypted bundle flow)
- [ ] `src/aiproxyguard/scanner/pipeline.py` (modify - expiration checks)
- [ ] `src/aiproxyguard/scanner/ml/license.py` (deprecate, import from crypto/)
- [ ] `tests/unit/test_crypto_license.py` (new)
- [ ] `tests/unit/test_signature_bundle.py` (new)
- [ ] `tests/unit/test_signature_cache.py` (new)

### Cloud (aiproxyguard-cloud)
- [ ] `server/app/services/bundle_encryption.py` (new)
- [ ] `server/app/api/v1/signatures.py` (modify - license endpoint)
- [ ] `server/app/models/bundle_license.py` (new - tracking)
- [ ] Database migration for license tracking

## Open Questions (Resolved)

1. ~~Should free-tier signatures also be encrypted?~~ **No** - unnecessary overhead
2. ~~License duration: 30 days or configurable?~~ **30 days default**, enterprise can request longer
3. ~~Grace period when license expires?~~ **No grace** - falls back to free signatures only
4. ~~Offline mode duration?~~ **Same as license (30 days)**, cached encrypted + license
