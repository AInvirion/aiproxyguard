# Copyright 2025-2026 AInvirion LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Generic license validation and content decryption.

This module handles both ML models and signature bundles using the same
envelope encryption scheme:

1. Content is encrypted once with a content-specific DEK (Data Encryption Key)
2. Licenses wrap the DEK with account-specific metadata and expiration
3. Licenses are signed with Ed25519 for integrity
4. Content is decrypted using AES-256-GCM

Supported content types:
- ML models: format "aiproxyguard-encrypted-model-v1"
- Signature bundles: format "aiproxyguard-encrypted-bundle-v1"
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _parse_iso_timestamp(timestamp_str: str) -> datetime:
    """Parse ISO timestamp string handling 'Z' suffix and ensuring timezone awareness.

    Args:
        timestamp_str: ISO format timestamp (may end with 'Z' or offset like '+00:00')

    Returns:
        Timezone-aware datetime in UTC
    """
    # Replace 'Z' suffix with '+00:00' for fromisoformat compatibility
    normalized = timestamp_str.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)

    # Ensure timezone awareness - if naive, assume UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt


@dataclass
class License:
    """Generic license for encrypted content (ML models or signature bundles).

    Attributes:
        license_id: Unique license identifier
        license_type: Type of content ("ml_model" or "signature_bundle")
        resource_id: ID of the licensed resource (model_id or bundle_id)
        resource_version: Version of the licensed resource
        account_id: Account that owns this license
        tier: Subscription tier ("free", "pro", "enterprise")
        dek: Data Encryption Key (decoded bytes)
        issued_at: When the license was issued
        expires_at: When the license expires
        signature: Ed25519 signature for integrity
        download_url: Optional URL to download the encrypted content
    """

    license_id: str
    license_type: str
    resource_id: str
    resource_version: str
    account_id: str
    tier: str
    dek: bytes
    issued_at: datetime
    expires_at: datetime
    signature: str
    download_url: str | None = None
    bound_instance_id: str | None = None  # Instance this license is bound to


@dataclass
class EncryptedContentHeader:
    """Header from encrypted content file (model or bundle).

    Attributes:
        format: Content format identifier
        resource_id: ID of the resource (model_id or bundle_id)
        version: Version of the resource
        nonce: AES-GCM nonce (decoded bytes)
        sha256_plaintext: SHA-256 hash of the decrypted content
    """

    format: str
    resource_id: str
    version: str
    nonce: bytes
    sha256_plaintext: str


# Valid content formats
VALID_FORMATS = {
    "aiproxyguard-encrypted-model-v1",
    "aiproxyguard-encrypted-bundle-v1",
}


def parse_license(license_data: dict[str, Any]) -> License:
    """Parse license dict into License object.

    Supports both ML model licenses and signature bundle licenses.

    Args:
        license_data: License dict from API response

    Returns:
        Parsed License object

    Raises:
        ValueError: If license format is invalid or missing required fields
    """
    # Determine license type and extract resource ID
    license_type = license_data.get("license_type", "ml_model")

    if license_type == "signature_bundle":
        resource_id = license_data.get("bundle_id", "")
        resource_version = license_data.get("bundle_version", "")
    else:
        # ML model (default for backwards compatibility)
        resource_id = license_data.get("model_id", "")
        resource_version = license_data.get("model_version", "")

    # Required fields
    required_base = ["license_id", "account_id", "tier", "dek", "issued_at", "expires_at", "signature"]
    for field in required_base:
        if field not in license_data:
            raise ValueError(f"Missing required field: {field}")

    if not resource_id:
        raise ValueError("Missing resource ID (model_id or bundle_id)")

    return License(
        license_id=license_data["license_id"],
        license_type=license_type,
        resource_id=resource_id,
        resource_version=resource_version,
        account_id=license_data["account_id"],
        tier=license_data["tier"],
        dek=base64.b64decode(license_data["dek"]),
        issued_at=_parse_iso_timestamp(license_data["issued_at"]),
        expires_at=_parse_iso_timestamp(license_data["expires_at"]),
        signature=license_data["signature"],
        download_url=license_data.get("download_url"),
        bound_instance_id=license_data.get("bound_instance_id"),
    )


def verify_license_signature(license_data: dict[str, Any], public_key_b64: str) -> bool:
    """Verify license signature using Ed25519.

    Args:
        license_data: License dict with signature
        public_key_b64: Base64-encoded Ed25519 public key

    Returns:
        True if signature is valid
    """
    if not public_key_b64:
        logger.warning("No public key configured for license verification")
        return False

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        signature_b64 = license_data.get("signature")
        if not signature_b64:
            logger.warning("License missing signature")
            return False

        # Recreate canonical JSON (exclude signature field)
        data_to_verify = {k: v for k, v in license_data.items() if k != "signature"}
        canonical = json.dumps(data_to_verify, sort_keys=True, separators=(",", ":"))

        # Verify
        public_key_bytes = base64.b64decode(public_key_b64)
        signature_bytes = base64.b64decode(signature_b64)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, canonical.encode())

        return True
    except ImportError:
        logger.warning("cryptography package not installed for license verification")
        return False
    except Exception as e:
        logger.warning(f"License signature verification failed: {e}")
        return False


def is_license_valid(
    license: License,
    public_key_b64: str,
    license_data: dict[str, Any],
    current_instance_id: str | None = None,
) -> tuple[bool, str]:
    """Check if license is valid (signature OK, not expired, instance bound).

    Args:
        license: Parsed License object
        public_key_b64: Ed25519 public key for signature verification
        license_data: Original license dict (for signature verification)
        current_instance_id: Current instance ID for binding validation

    Returns:
        (is_valid, reason) tuple
    """
    # Check signature
    if not verify_license_signature(license_data, public_key_b64):
        return False, "Invalid signature"

    # Check expiration
    now = datetime.now(timezone.utc)
    if now > license.expires_at:
        return False, f"License expired at {license.expires_at.isoformat()}"

    # Check instance binding (if license is bound to a specific instance)
    if license.bound_instance_id:
        if not current_instance_id:
            return False, "License is instance-bound but no instance ID provided"
        if license.bound_instance_id != current_instance_id:
            logger.warning(
                f"License instance mismatch: bound to {license.bound_instance_id[:8]}..., "
                f"current is {current_instance_id[:8]}..."
            )
            return False, "License bound to different instance"

    return True, "Valid"


def parse_encrypted_header(data: bytes) -> tuple[EncryptedContentHeader, bytes]:
    """Parse header from encrypted content file.

    The encrypted content format is:
        [4 bytes: header length (big-endian)][JSON header][AES-GCM ciphertext]

    Args:
        data: Raw encrypted content bytes

    Returns:
        (header, ciphertext) tuple

    Raises:
        ValueError: If file is corrupted or header is invalid
    """
    if len(data) < 4:
        raise ValueError("Encrypted content too small (missing header length)")

    header_len = int.from_bytes(data[:4], "big")

    # Validate header length against actual file size
    if header_len > len(data) - 4:
        raise ValueError(
            f"Invalid header length {header_len} for content of size {len(data)}"
        )
    if header_len > 1024 * 1024:  # 1MB max header
        raise ValueError(f"Header length {header_len} exceeds maximum (1MB)")

    header_json = data[4 : 4 + header_len]
    ciphertext = data[4 + header_len :]

    try:
        header_dict = json.loads(header_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in header: {e}") from e

    content_format = header_dict.get("format", "")
    if content_format not in VALID_FORMATS:
        raise ValueError(f"Unknown format: {content_format}")

    # Extract resource ID based on format
    if "bundle" in content_format:
        resource_id = header_dict.get("bundle_id", "")
    else:
        resource_id = header_dict.get("model_id", "")

    return EncryptedContentHeader(
        format=content_format,
        resource_id=resource_id,
        version=header_dict.get("version", ""),
        nonce=base64.b64decode(header_dict["nonce"]),
        sha256_plaintext=header_dict["sha256_plaintext"],
    ), ciphertext


def decrypt_content(
    encrypted_data: bytes,
    dek: bytes,
    expected_format: str | None = None,
) -> bytes:
    """Decrypt AES-256-GCM encrypted content.

    Args:
        encrypted_data: Raw encrypted content bytes (header + ciphertext)
        dek: Data Encryption Key from license
        expected_format: Optional format to validate against

    Returns:
        Decrypted content bytes

    Raises:
        ValueError: If decryption fails or integrity check fails
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:
        raise ValueError(
            "cryptography package required for content decryption. "
            "Install with: pip install aiproxyguard[ml]"
        ) from e

    # Parse header
    header, ciphertext = parse_encrypted_header(encrypted_data)

    # Validate format if specified
    if expected_format and header.format != expected_format:
        raise ValueError(f"Format mismatch: expected {expected_format}, got {header.format}")

    # Additional Authenticated Data (AAD)
    aad = f"{header.resource_id}:{header.version}".encode()

    # Decrypt
    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(header.nonce, ciphertext, aad)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}") from e

    # Verify hash
    actual_hash = hashlib.sha256(plaintext).hexdigest()
    if actual_hash != header.sha256_plaintext:
        raise ValueError("Content integrity check failed")

    logger.info(
        "Content decrypted successfully",
        extra={
            "format": header.format,
            "resource_id": header.resource_id,
            "version": header.version,
            "size": len(plaintext),
        },
    )

    return plaintext
