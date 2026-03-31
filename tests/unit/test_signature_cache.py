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

"""Unit tests for signature cache module."""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aiproxyguard.signatures.cache import (
    clear_bundle_cache,
    clear_expired_cache,
    get_cache_stats,
    list_cached_bundles,
    load_bundle_cache,
    save_bundle_cache,
)


@pytest.fixture
def temp_cache_dir(monkeypatch):
    """Create a temporary cache directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("AIPROXYGUARD_CACHE_DIR", tmpdir)
        yield Path(tmpdir)


class TestSaveBundleCache:
    """Tests for save_bundle_cache function."""

    def test_save_creates_files(self, temp_cache_dir) -> None:
        """Test that saving creates expected files."""
        license_data = {
            "license_id": "lic_123",
            "bundle_id": "test-bundle",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        }

        result = save_bundle_cache("test-bundle", b"encrypted_content", license_data)

        assert result is True
        bundle_path = temp_cache_dir / "bundles" / "test-bundle"
        assert (bundle_path / "bundle.enc").exists()
        assert (bundle_path / "license.json").exists()
        assert (bundle_path / "metadata.json").exists()

    def test_save_content_is_correct(self, temp_cache_dir) -> None:
        """Test that saved content matches input."""
        encrypted_data = b"test_encrypted_bytes_12345"
        license_data = {
            "license_id": "lic_456",
            "expires_at": "2024-04-26T00:00:00Z",
        }

        save_bundle_cache("my-bundle", encrypted_data, license_data)

        bundle_path = temp_cache_dir / "bundles" / "my-bundle"
        assert (bundle_path / "bundle.enc").read_bytes() == encrypted_data

        saved_license = json.loads((bundle_path / "license.json").read_text())
        assert saved_license["license_id"] == "lic_456"

    def test_save_cache_mode_none_skips_caching(self, temp_cache_dir) -> None:
        """Test that cache_mode='none' doesn't create any files."""
        license_data = {
            "license_id": "lic_789",
            "dek": "base64dekvalue",
            "expires_at": "2024-04-26T00:00:00Z",
        }

        result = save_bundle_cache(
            "no-cache-bundle", b"encrypted", license_data, cache_mode="none"
        )

        assert result is False
        bundle_path = temp_cache_dir / "bundles" / "no-cache-bundle"
        assert not bundle_path.exists()

    def test_save_cache_mode_encrypted_only_removes_dek(self, temp_cache_dir) -> None:
        """Test that cache_mode='encrypted_only' saves license without DEK."""
        license_data = {
            "license_id": "lic_secure",
            "dek": "supersecretdekvalue",
            "expires_at": "2024-04-26T00:00:00Z",
            "account_id": "acc_123",
        }

        result = save_bundle_cache(
            "secure-bundle", b"encrypted_content", license_data, cache_mode="encrypted_only"
        )

        assert result is True
        bundle_path = temp_cache_dir / "bundles" / "secure-bundle"
        assert (bundle_path / "bundle.enc").exists()

        saved_license = json.loads((bundle_path / "license.json").read_text())
        assert "dek" not in saved_license  # DEK should be stripped
        assert saved_license["license_id"] == "lic_secure"
        assert saved_license["account_id"] == "acc_123"

        # Verify metadata includes cache_mode
        metadata = json.loads((bundle_path / "metadata.json").read_text())
        assert metadata["cache_mode"] == "encrypted_only"

    def test_save_cache_mode_full_preserves_dek(self, temp_cache_dir) -> None:
        """Test that cache_mode='full' preserves DEK in license."""
        license_data = {
            "license_id": "lic_full",
            "dek": "mydekvalue",
            "expires_at": "2024-04-26T00:00:00Z",
        }

        result = save_bundle_cache(
            "full-bundle", b"encrypted", license_data, cache_mode="full"
        )

        assert result is True
        bundle_path = temp_cache_dir / "bundles" / "full-bundle"
        saved_license = json.loads((bundle_path / "license.json").read_text())
        assert saved_license["dek"] == "mydekvalue"  # DEK preserved


class TestLoadBundleCache:
    """Tests for load_bundle_cache function."""

    def test_load_returns_saved_data(self, temp_cache_dir) -> None:
        """Test loading returns what was saved."""
        future = datetime.now(timezone.utc) + timedelta(days=30)
        license_data = {
            "license_id": "lic_789",
            "expires_at": future.isoformat(),
        }
        encrypted_data = b"my_encrypted_bytes"

        save_bundle_cache("load-test", encrypted_data, license_data)
        result = load_bundle_cache("load-test")

        assert result is not None
        loaded_bytes, loaded_license = result
        assert loaded_bytes == encrypted_data
        assert loaded_license["license_id"] == "lic_789"

    def test_load_nonexistent_returns_none(self, temp_cache_dir) -> None:
        """Test loading nonexistent bundle returns None."""
        result = load_bundle_cache("nonexistent-bundle")
        assert result is None

    def test_load_expired_returns_none(self, temp_cache_dir) -> None:
        """Test loading expired bundle returns None."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        license_data = {
            "license_id": "lic_expired",
            "expires_at": past.isoformat(),
        }

        save_bundle_cache("expired-bundle", b"data", license_data)
        result = load_bundle_cache("expired-bundle")

        assert result is None


class TestListCachedBundles:
    """Tests for list_cached_bundles function."""

    def test_list_empty_cache(self, temp_cache_dir) -> None:
        """Test listing empty cache."""
        result = list_cached_bundles()
        assert result == []

    def test_list_multiple_bundles(self, temp_cache_dir) -> None:
        """Test listing multiple cached bundles."""
        future = datetime.now(timezone.utc) + timedelta(days=30)
        license_data = {"expires_at": future.isoformat()}

        save_bundle_cache("bundle-a", b"data-a", license_data)
        save_bundle_cache("bundle-b", b"data-b", license_data)
        save_bundle_cache("bundle-c", b"data-c", license_data)

        result = list_cached_bundles()

        assert len(result) == 3
        assert "bundle-a" in result
        assert "bundle-b" in result
        assert "bundle-c" in result


class TestClearBundleCache:
    """Tests for clear_bundle_cache function."""

    def test_clear_removes_bundle(self, temp_cache_dir) -> None:
        """Test clearing a specific bundle."""
        license_data = {"expires_at": "2099-01-01T00:00:00Z"}
        save_bundle_cache("to-clear", b"data", license_data)

        assert "to-clear" in list_cached_bundles()

        result = clear_bundle_cache("to-clear")

        assert result is True
        assert "to-clear" not in list_cached_bundles()

    def test_clear_nonexistent_returns_false(self, temp_cache_dir) -> None:
        """Test clearing nonexistent bundle returns False."""
        result = clear_bundle_cache("nonexistent")
        assert result is False


class TestClearExpiredCache:
    """Tests for clear_expired_cache function."""

    def test_clear_only_expired(self, temp_cache_dir) -> None:
        """Test that only expired bundles are cleared."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        future = datetime.now(timezone.utc) + timedelta(days=30)

        save_bundle_cache("active", b"data", {"expires_at": future.isoformat()})
        save_bundle_cache("expired-1", b"data", {"expires_at": past.isoformat()})
        save_bundle_cache("expired-2", b"data", {"expires_at": past.isoformat()})

        removed = clear_expired_cache()

        assert removed == 2
        assert "active" in list_cached_bundles()
        assert "expired-1" not in list_cached_bundles()
        assert "expired-2" not in list_cached_bundles()


class TestGetCacheStats:
    """Tests for get_cache_stats function."""

    def test_stats_empty_cache(self, temp_cache_dir) -> None:
        """Test stats on empty cache."""
        stats = get_cache_stats()

        assert stats["total_bundles"] == 0
        assert stats["total_size_bytes"] == 0
        assert stats["expired_bundles"] == 0

    def test_stats_with_bundles(self, temp_cache_dir) -> None:
        """Test stats with bundles."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        future = datetime.now(timezone.utc) + timedelta(days=30)

        save_bundle_cache("active", b"x" * 100, {"expires_at": future.isoformat()})
        save_bundle_cache("expired", b"y" * 50, {"expires_at": past.isoformat()})

        stats = get_cache_stats()

        assert stats["total_bundles"] == 2
        assert stats["total_size_bytes"] > 0
        assert stats["expired_bundles"] == 1
