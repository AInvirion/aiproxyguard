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

"""License validation and model decryption for encrypted ML models.

The license contains:
- DEK (Data Encryption Key) for AES-256-GCM decryption
- Expiration timestamp
- Ed25519 signature for integrity

The proxy:
1. Downloads encrypted model from cloud
2. Validates license signature and expiration
3. Extracts DEK from license
4. Decrypts model and loads into classifier
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
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
    """Parsed license data."""
    license_id: str
    model_id: str
    model_version: str
    account_id: str
    tier: str
    dek: bytes  # Decoded DEK
    issued_at: datetime
    expires_at: datetime
    signature: str


@dataclass
class EncryptedModelHeader:
    """Header from encrypted model file."""
    format: str
    model_id: str
    version: str
    nonce: bytes
    sha256_plaintext: str


def parse_license(license_data: dict[str, Any]) -> License:
    """
    Parse license dict into License object.

    Args:
        license_data: License dict from API response

    Returns:
        Parsed License object

    Raises:
        ValueError: If license format is invalid
    """
    required_fields = [
        "license_id", "model_id", "model_version", "account_id",
        "tier", "dek", "issued_at", "expires_at", "signature"
    ]
    for field in required_fields:
        if field not in license_data:
            raise ValueError(f"Missing required field: {field}")

    return License(
        license_id=license_data["license_id"],
        model_id=license_data["model_id"],
        model_version=license_data["model_version"],
        account_id=license_data["account_id"],
        tier=license_data["tier"],
        dek=base64.b64decode(license_data["dek"]),
        issued_at=_parse_iso_timestamp(license_data["issued_at"]),
        expires_at=_parse_iso_timestamp(license_data["expires_at"]),
        signature=license_data["signature"],
    )


def verify_license_signature(license_data: dict[str, Any], public_key_b64: str) -> bool:
    """
    Verify license signature using Ed25519.

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


def is_license_valid(license: License, public_key_b64: str, license_data: dict[str, Any]) -> tuple[bool, str]:
    """
    Check if license is valid (signature OK and not expired).

    Args:
        license: Parsed License object
        public_key_b64: Ed25519 public key
        license_data: Original license dict (for signature verification)

    Returns:
        (is_valid, reason) tuple
    """
    # Check signature
    if not verify_license_signature(license_data, public_key_b64):
        return False, "Invalid signature"

    # Check expiration
    if datetime.now(timezone.utc) > license.expires_at:
        return False, f"License expired at {license.expires_at.isoformat()}"

    return True, "Valid"


def parse_encrypted_model_header(data: bytes) -> tuple[EncryptedModelHeader, bytes]:
    """
    Parse header from encrypted model file.

    Args:
        data: Raw encrypted model bytes

    Returns:
        (header, ciphertext) tuple

    Raises:
        ValueError: If file is corrupted or header length is invalid
    """
    if len(data) < 4:
        raise ValueError("Encrypted model file too small (missing header length)")

    header_len = int.from_bytes(data[:4], "big")

    # Validate header length against actual file size
    if header_len > len(data) - 4:
        raise ValueError(
            f"Invalid header length {header_len} for file of size {len(data)}"
        )
    if header_len > 1024 * 1024:  # 1MB max header
        raise ValueError(f"Header length {header_len} exceeds maximum (1MB)")

    header_json = data[4:4 + header_len]
    ciphertext = data[4 + header_len:]

    try:
        header_dict = json.loads(header_json)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in header: {e}") from e

    if header_dict.get("format") != "aiproxyguard-encrypted-model-v1":
        raise ValueError(f"Unknown format: {header_dict.get('format')}")

    return EncryptedModelHeader(
        format=header_dict["format"],
        model_id=header_dict["model_id"],
        version=header_dict["version"],
        nonce=base64.b64decode(header_dict["nonce"]),
        sha256_plaintext=header_dict["sha256_plaintext"],
    ), ciphertext


def decrypt_model(encrypted_data: bytes, dek: bytes) -> bytes:
    """
    Decrypt model using license DEK.

    Args:
        encrypted_data: Raw encrypted model file
        dek: Data Encryption Key from license

    Returns:
        Decrypted model bytes

    Raises:
        ValueError: If decryption fails or integrity check fails
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:
        raise ValueError(
            "cryptography package required for model decryption. "
            "Install with: pip install aiproxyguard[ml]"
        ) from e

    # Parse header
    header, ciphertext = parse_encrypted_model_header(encrypted_data)

    # Additional Authenticated Data
    aad = f"{header.model_id}:{header.version}".encode()

    # Decrypt
    aesgcm = AESGCM(dek)
    try:
        plaintext = aesgcm.decrypt(header.nonce, ciphertext, aad)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}") from e

    # Verify hash
    actual_hash = hashlib.sha256(plaintext).hexdigest()
    if actual_hash != header.sha256_plaintext:
        raise ValueError("Model integrity check failed")

    logger.info(
        f"Model decrypted successfully",
        extra={
            "model_id": header.model_id,
            "version": header.version,
            "size": len(plaintext),
        }
    )

    return plaintext


def load_licensed_model(
    encrypted_path: Path,
    license_data: dict[str, Any],
    public_key_b64: str,
) -> bytes:
    """
    Load and decrypt a licensed model.

    Args:
        encrypted_path: Path to encrypted model file
        license_data: License dict from API
        public_key_b64: Ed25519 public key for verification

    Returns:
        Decrypted model bytes ready for loading

    Raises:
        ValueError: If license invalid or decryption fails
    """
    # Parse and validate license
    license = parse_license(license_data)

    is_valid, reason = is_license_valid(license, public_key_b64, license_data)
    if not is_valid:
        raise ValueError(f"Invalid license: {reason}")

    # Read encrypted file
    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()

    # Decrypt
    return decrypt_model(encrypted_data, license.dek)


def save_decrypted_model(model_bytes: bytes, output_path: Path) -> None:
    """
    Save decrypted model to disk.

    Args:
        model_bytes: Decrypted model data
        output_path: Where to save the model
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(model_bytes)
    logger.info(f"Decrypted model saved to {output_path}")
