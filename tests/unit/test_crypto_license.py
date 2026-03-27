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

"""Unit tests for crypto license module."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from aiproxyguard.crypto.license import (
    License,
    parse_license,
    is_license_valid,
    parse_encrypted_header,
    _parse_iso_timestamp,
)


class TestParseIsoTimestamp:
    """Tests for ISO timestamp parsing."""

    def test_parse_z_suffix(self) -> None:
        """Test parsing timestamp with Z suffix."""
        result = _parse_iso_timestamp("2024-03-26T12:00:00Z")
        assert result.tzinfo is not None
        assert result.year == 2024
        assert result.month == 3
        assert result.day == 26

    def test_parse_offset_suffix(self) -> None:
        """Test parsing timestamp with offset."""
        result = _parse_iso_timestamp("2024-03-26T12:00:00+00:00")
        assert result.tzinfo is not None

    def test_parse_naive_assumes_utc(self) -> None:
        """Test that naive timestamps are assumed UTC."""
        result = _parse_iso_timestamp("2024-03-26T12:00:00")
        assert result.tzinfo == timezone.utc


class TestParseLicense:
    """Tests for license parsing."""

    def test_parse_ml_model_license(self) -> None:
        """Test parsing ML model license."""
        license_data = {
            "license_id": "lic_123",
            "license_type": "ml_model",
            "model_id": "model_456",
            "model_version": "1.0.0",
            "account_id": "acc_789",
            "tier": "pro",
            "dek": base64.b64encode(b"0" * 32).decode(),
            "issued_at": "2024-03-26T00:00:00Z",
            "expires_at": "2024-04-26T00:00:00Z",
            "signature": "sig_abc",
            "download_url": "https://example.com/model.enc",
        }

        result = parse_license(license_data)

        assert result.license_id == "lic_123"
        assert result.license_type == "ml_model"
        assert result.resource_id == "model_456"
        assert result.resource_version == "1.0.0"
        assert result.tier == "pro"
        assert len(result.dek) == 32
        assert result.download_url == "https://example.com/model.enc"

    def test_parse_signature_bundle_license(self) -> None:
        """Test parsing signature bundle license."""
        license_data = {
            "license_id": "lic_456",
            "license_type": "signature_bundle",
            "bundle_id": "sig-enterprise-v1",
            "bundle_version": "2024.03.26",
            "account_id": "acc_789",
            "tier": "enterprise",
            "dek": base64.b64encode(b"1" * 32).decode(),
            "issued_at": "2024-03-26T00:00:00Z",
            "expires_at": "2024-04-26T00:00:00Z",
            "signature": "sig_def",
        }

        result = parse_license(license_data)

        assert result.license_type == "signature_bundle"
        assert result.resource_id == "sig-enterprise-v1"
        assert result.resource_version == "2024.03.26"
        assert result.tier == "enterprise"

    def test_parse_missing_required_field(self) -> None:
        """Test that missing required field raises error."""
        license_data = {
            "license_id": "lic_123",
            # Missing other required fields
        }

        with pytest.raises(ValueError, match="Missing required field"):
            parse_license(license_data)

    def test_parse_missing_resource_id(self) -> None:
        """Test that missing resource ID raises error."""
        license_data = {
            "license_id": "lic_123",
            "license_type": "ml_model",
            # Missing model_id
            "account_id": "acc_789",
            "tier": "pro",
            "dek": base64.b64encode(b"0" * 32).decode(),
            "issued_at": "2024-03-26T00:00:00Z",
            "expires_at": "2024-04-26T00:00:00Z",
            "signature": "sig_abc",
        }

        with pytest.raises(ValueError, match="Missing resource ID"):
            parse_license(license_data)


class TestIsLicenseValid:
    """Tests for license validation."""

    def test_expired_license(self) -> None:
        """Test that expired license is invalid."""
        past = datetime.now(timezone.utc) - timedelta(days=1)
        license = License(
            license_id="lic_123",
            license_type="ml_model",
            resource_id="model_456",
            resource_version="1.0.0",
            account_id="acc_789",
            tier="pro",
            dek=b"0" * 32,
            issued_at=past - timedelta(days=30),
            expires_at=past,
            signature="sig_abc",
        )

        # Create matching license_data for signature check
        license_data = {
            "license_id": "lic_123",
            "license_type": "ml_model",
            "model_id": "model_456",
            "expires_at": past.isoformat(),
        }

        valid, reason = is_license_valid(license, "", license_data)

        assert not valid
        assert "expired" in reason.lower() or "signature" in reason.lower()


class TestParseEncryptedHeader:
    """Tests for encrypted content header parsing."""

    def test_parse_model_header(self) -> None:
        """Test parsing model header."""
        header = {
            "format": "aiproxyguard-encrypted-model-v1",
            "model_id": "model_123",
            "version": "1.0.0",
            "nonce": base64.b64encode(b"0" * 12).decode(),
            "sha256_plaintext": "abc123",
        }
        header_bytes = json.dumps(header).encode()
        data = len(header_bytes).to_bytes(4, "big") + header_bytes + b"ciphertext"

        result, ciphertext = parse_encrypted_header(data)

        assert result.format == "aiproxyguard-encrypted-model-v1"
        assert result.resource_id == "model_123"
        assert result.version == "1.0.0"
        assert len(result.nonce) == 12
        assert ciphertext == b"ciphertext"

    def test_parse_bundle_header(self) -> None:
        """Test parsing bundle header."""
        header = {
            "format": "aiproxyguard-encrypted-bundle-v1",
            "bundle_id": "sig-enterprise-v1",
            "version": "2024.03.26",
            "nonce": base64.b64encode(b"1" * 12).decode(),
            "sha256_plaintext": "def456",
        }
        header_bytes = json.dumps(header).encode()
        data = len(header_bytes).to_bytes(4, "big") + header_bytes + b"encrypted"

        result, ciphertext = parse_encrypted_header(data)

        assert result.format == "aiproxyguard-encrypted-bundle-v1"
        assert result.resource_id == "sig-enterprise-v1"

    def test_parse_invalid_format(self) -> None:
        """Test that invalid format raises error."""
        header = {
            "format": "invalid-format",
            "model_id": "model_123",
            "version": "1.0.0",
            "nonce": base64.b64encode(b"0" * 12).decode(),
            "sha256_plaintext": "abc123",
        }
        header_bytes = json.dumps(header).encode()
        data = len(header_bytes).to_bytes(4, "big") + header_bytes + b"ciphertext"

        with pytest.raises(ValueError, match="Unknown format"):
            parse_encrypted_header(data)

    def test_parse_too_small(self) -> None:
        """Test that too small data raises error."""
        with pytest.raises(ValueError, match="too small"):
            parse_encrypted_header(b"abc")

    def test_parse_invalid_header_length(self) -> None:
        """Test that invalid header length raises error."""
        # Header length says 1000 but data is much smaller
        data = (1000).to_bytes(4, "big") + b"short"

        with pytest.raises(ValueError, match="Invalid header length"):
            parse_encrypted_header(data)
