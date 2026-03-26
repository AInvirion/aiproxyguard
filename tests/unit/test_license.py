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

"""Unit tests for ML license module."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone, timedelta

import pytest


class TestParseLicense:
    """Tests for parse_license function."""

    def test_parse_valid_license(self) -> None:
        """Test parsing a valid license dict."""
        from aiproxyguard.scanner.ml.license import parse_license

        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=7)

        license_data = {
            "license_id": "test-license-123",
            "model_id": "prompt-classifier-v1",
            "model_version": "1.0.0",
            "account_id": "account-456",
            "tier": "pro",
            "dek": base64.b64encode(secrets.token_bytes(32)).decode(),
            "issued_at": now.isoformat(),
            "expires_at": expires.isoformat(),
            "signature": "test-signature",
        }

        license = parse_license(license_data)

        assert license.license_id == "test-license-123"
        assert license.model_id == "prompt-classifier-v1"
        assert license.model_version == "1.0.0"
        assert license.tier == "pro"
        assert len(license.dek) == 32

    def test_parse_missing_field(self) -> None:
        """Test that missing fields raise ValueError."""
        from aiproxyguard.scanner.ml.license import parse_license

        license_data = {
            "license_id": "test",
            # Missing other fields
        }

        with pytest.raises(ValueError, match="Missing required field"):
            parse_license(license_data)


class TestLicenseValidation:
    """Tests for license validation functions."""

    def test_expired_license(self) -> None:
        """Test that expired license is rejected."""
        from aiproxyguard.scanner.ml.license import parse_license, is_license_valid

        past = datetime.now(timezone.utc) - timedelta(days=1)
        expired = datetime.now(timezone.utc) - timedelta(hours=1)

        license_data = {
            "license_id": "test-license",
            "model_id": "test-model",
            "model_version": "1.0.0",
            "account_id": "test-account",
            "tier": "pro",
            "dek": base64.b64encode(secrets.token_bytes(32)).decode(),
            "issued_at": past.isoformat(),
            "expires_at": expired.isoformat(),
            "signature": "invalid",
        }

        license = parse_license(license_data)

        # Without valid signature, should fail
        is_valid, reason = is_license_valid(license, "", license_data)
        assert not is_valid
        assert "Invalid signature" in reason

    def test_valid_license_no_crypto(self) -> None:
        """Test license validation without cryptography (signature fails gracefully)."""
        from aiproxyguard.scanner.ml.license import verify_license_signature

        license_data = {
            "license_id": "test",
            "signature": "invalid",
        }

        # Should return False gracefully
        result = verify_license_signature(license_data, "")
        assert result is False


class TestEncryptedModelHeader:
    """Tests for encrypted model header parsing."""

    def test_parse_header(self) -> None:
        """Test parsing encrypted model header."""
        from aiproxyguard.scanner.ml.license import parse_encrypted_model_header

        header = {
            "format": "aiproxyguard-encrypted-model-v1",
            "model_id": "test-model",
            "version": "1.0.0",
            "nonce": base64.b64encode(secrets.token_bytes(12)).decode(),
            "sha256_plaintext": hashlib.sha256(b"test").hexdigest(),
        }
        header_json = json.dumps(header).encode()
        header_len = len(header_json).to_bytes(4, "big")
        ciphertext = b"encrypted-data-here"

        data = header_len + header_json + ciphertext

        parsed_header, parsed_ciphertext = parse_encrypted_model_header(data)

        assert parsed_header.model_id == "test-model"
        assert parsed_header.version == "1.0.0"
        assert len(parsed_header.nonce) == 12
        assert parsed_ciphertext == ciphertext

    def test_parse_invalid_format(self) -> None:
        """Test that invalid format raises ValueError."""
        from aiproxyguard.scanner.ml.license import parse_encrypted_model_header

        header = {
            "format": "unknown-format",
            "model_id": "test",
            "version": "1.0",
            "nonce": base64.b64encode(b"x" * 12).decode(),
            "sha256_plaintext": "abc",
        }
        header_json = json.dumps(header).encode()
        header_len = len(header_json).to_bytes(4, "big")

        data = header_len + header_json + b"data"

        with pytest.raises(ValueError, match="Unknown format"):
            parse_encrypted_model_header(data)


class TestDecryption:
    """Tests for model decryption."""

    def test_decrypt_model_roundtrip(self) -> None:
        """Test encrypt/decrypt roundtrip."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            pytest.skip("cryptography not installed")

        from aiproxyguard.scanner.ml.license import decrypt_model

        # Create test data
        model_data = b"test model data for encryption roundtrip"
        model_id = "test-model"
        version = "1.0.0"
        dek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        # Encrypt
        aad = f"{model_id}:{version}".encode()
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, model_data, aad)

        # Create header
        header = {
            "format": "aiproxyguard-encrypted-model-v1",
            "model_id": model_id,
            "version": version,
            "nonce": base64.b64encode(nonce).decode(),
            "sha256_plaintext": hashlib.sha256(model_data).hexdigest(),
        }
        header_json = json.dumps(header).encode()
        header_len = len(header_json).to_bytes(4, "big")

        encrypted_data = header_len + header_json + ciphertext

        # Decrypt
        decrypted = decrypt_model(encrypted_data, dek)

        assert decrypted == model_data

    def test_decrypt_wrong_key(self) -> None:
        """Test that wrong key fails decryption."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            pytest.skip("cryptography not installed")

        from aiproxyguard.scanner.ml.license import decrypt_model

        model_data = b"secret model"
        model_id = "test"
        version = "1.0"
        correct_dek = secrets.token_bytes(32)
        wrong_dek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        # Encrypt with correct key
        aad = f"{model_id}:{version}".encode()
        aesgcm = AESGCM(correct_dek)
        ciphertext = aesgcm.encrypt(nonce, model_data, aad)

        header = {
            "format": "aiproxyguard-encrypted-model-v1",
            "model_id": model_id,
            "version": version,
            "nonce": base64.b64encode(nonce).decode(),
            "sha256_plaintext": hashlib.sha256(model_data).hexdigest(),
        }
        header_json = json.dumps(header).encode()
        header_len = len(header_json).to_bytes(4, "big")
        encrypted_data = header_len + header_json + ciphertext

        # Decrypt with wrong key should fail
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_model(encrypted_data, wrong_dek)

    def test_decrypt_tampered_data(self) -> None:
        """Test that tampered ciphertext fails."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            pytest.skip("cryptography not installed")

        from aiproxyguard.scanner.ml.license import decrypt_model

        model_data = b"original model data"
        model_id = "test"
        version = "1.0"
        dek = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        aad = f"{model_id}:{version}".encode()
        aesgcm = AESGCM(dek)
        ciphertext = aesgcm.encrypt(nonce, model_data, aad)

        # Tamper with ciphertext
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0xFF
        tampered_ciphertext = bytes(tampered_ciphertext)

        header = {
            "format": "aiproxyguard-encrypted-model-v1",
            "model_id": model_id,
            "version": version,
            "nonce": base64.b64encode(nonce).decode(),
            "sha256_plaintext": hashlib.sha256(model_data).hexdigest(),
        }
        header_json = json.dumps(header).encode()
        header_len = len(header_json).to_bytes(4, "big")
        encrypted_data = header_len + header_json + tampered_ciphertext

        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_model(encrypted_data, dek)
