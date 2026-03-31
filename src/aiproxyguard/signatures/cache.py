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

"""Local cache for encrypted signature bundles and licenses.

This module provides persistence for offline support:
- Encrypted bundles are stored on disk
- Licenses are stored alongside bundles
- On startup, if network is unavailable, cached bundles are used
- Expired licenses are automatically cleaned up
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default cache directory - can be overridden via environment variable
_DEFAULT_CACHE_DIR = Path("/var/lib/aiproxyguard/cache")
_USER_CACHE_DIR = Path.home() / ".aiproxyguard" / "cache"


def get_cache_dir() -> Path:
    """Get the cache directory path.

    Priority:
    1. AIPROXYGUARD_CACHE_DIR environment variable
    2. /var/lib/aiproxyguard/cache (if writable)
    3. ~/.aiproxyguard/cache (user fallback)

    Returns:
        Path to cache directory
    """
    # Check environment variable
    env_path = os.environ.get("AIPROXYGUARD_CACHE_DIR")
    if env_path:
        return Path(env_path)

    # Try system directory first
    if _DEFAULT_CACHE_DIR.exists() or _can_create_dir(_DEFAULT_CACHE_DIR):
        return _DEFAULT_CACHE_DIR

    # Fall back to user directory
    return _USER_CACHE_DIR


def _can_create_dir(path: Path) -> bool:
    """Check if we can create a directory at the given path."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        return True
    except (PermissionError, OSError):
        return False


def save_bundle_cache(
    bundle_id: str,
    encrypted_bytes: bytes,
    license_data: dict[str, Any],
    cache_mode: str = "full",
) -> bool:
    """Persist encrypted bundle + license for offline use.

    Args:
        bundle_id: Unique bundle identifier
        encrypted_bytes: Raw encrypted bundle data
        license_data: License dict from API
        cache_mode: Cache mode - "full" (default), "encrypted_only", or "none"
            - "full": Cache encrypted bundle + full license (including DEK)
            - "encrypted_only": Cache encrypted bundle + license WITHOUT DEK
            - "none": Don't cache anything

    Returns:
        True if cache was saved successfully
    """
    if cache_mode == "none":
        logger.debug(f"Cache mode is 'none', skipping cache for {bundle_id}")
        return False

    try:
        cache_dir = get_cache_dir()
        bundle_path = cache_dir / "bundles" / bundle_id
        bundle_path.mkdir(parents=True, exist_ok=True)

        # Save encrypted bundle
        bundle_file = bundle_path / "bundle.enc"
        bundle_file.write_bytes(encrypted_bytes)

        # Save license (optionally without DEK for security)
        if cache_mode == "encrypted_only":
            # Remove DEK from cached license - requires online fetch to decrypt
            license_to_save = {k: v for k, v in license_data.items() if k != "dek"}
            logger.debug(f"Caching {bundle_id} without DEK (encrypted_only mode)")
        else:
            license_to_save = license_data

        license_file = bundle_path / "license.json"
        license_file.write_text(json.dumps(license_to_save, indent=2))

        # Save metadata
        metadata = {
            "bundle_id": bundle_id,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": license_data.get("expires_at"),
            "version": license_data.get("bundle_version", license_data.get("version", "")),
            "cache_mode": cache_mode,
        }
        metadata_file = bundle_path / "metadata.json"
        metadata_file.write_text(json.dumps(metadata, indent=2))

        logger.debug(f"Cached bundle {bundle_id} to {bundle_path} (mode={cache_mode})")
        return True

    except Exception as e:
        logger.warning(f"Failed to cache bundle {bundle_id}: {e}")
        return False


def save_bundle_license(bundle_id: str, license_data: dict[str, Any]) -> bool:
    """Update just the license for a cached bundle (for license refresh).

    Args:
        bundle_id: Unique bundle identifier
        license_data: New license dict from API

    Returns:
        True if license was saved successfully
    """
    try:
        cache_dir = get_cache_dir()
        bundle_path = cache_dir / "bundles" / bundle_id

        if not bundle_path.exists():
            logger.debug(f"Bundle {bundle_id} not in cache, skipping license update")
            return False

        # Update license
        license_file = bundle_path / "license.json"
        license_file.write_text(json.dumps(license_data, indent=2))

        # Update metadata
        metadata_file = bundle_path / "metadata.json"
        if metadata_file.exists():
            metadata = json.loads(metadata_file.read_text())
        else:
            metadata = {"bundle_id": bundle_id}

        metadata["expires_at"] = license_data.get("expires_at")
        metadata["license_refreshed_at"] = datetime.now(timezone.utc).isoformat()
        metadata_file.write_text(json.dumps(metadata, indent=2))

        logger.debug(f"Refreshed license for cached bundle {bundle_id}")
        return True

    except Exception as e:
        logger.warning(f"Failed to save license for {bundle_id}: {e}")
        return False


def load_bundle_cache(bundle_id: str) -> tuple[bytes, dict[str, Any]] | None:
    """Load cached bundle + license if available and not expired.

    Args:
        bundle_id: Unique bundle identifier

    Returns:
        (encrypted_bytes, license_data) tuple, or None if not available/expired
    """
    try:
        cache_dir = get_cache_dir()
        bundle_path = cache_dir / "bundles" / bundle_id

        if not bundle_path.exists():
            return None

        # Load license first to check expiration
        license_file = bundle_path / "license.json"
        if not license_file.exists():
            logger.warning(f"Cached bundle {bundle_id} missing license")
            return None

        license_data = json.loads(license_file.read_text())

        # Check if license is expired
        expires_at_str = license_data.get("expires_at")
        if expires_at_str:
            expires_at = datetime.fromisoformat(
                expires_at_str.replace("Z", "+00:00")
            )
            if datetime.now(timezone.utc) > expires_at:
                logger.info(f"Cached license for {bundle_id} expired at {expires_at}")
                return None

        # Load encrypted bundle
        bundle_file = bundle_path / "bundle.enc"
        if not bundle_file.exists():
            logger.warning(f"Cached bundle {bundle_id} missing encrypted data")
            return None

        encrypted_bytes = bundle_file.read_bytes()

        logger.debug(f"Loaded cached bundle {bundle_id}")
        return encrypted_bytes, license_data

    except Exception as e:
        logger.warning(f"Failed to load cached bundle {bundle_id}: {e}")
        return None


def list_cached_bundles() -> list[str]:
    """List all cached bundle IDs.

    Returns:
        List of bundle IDs that have cached data
    """
    try:
        cache_dir = get_cache_dir()
        bundles_dir = cache_dir / "bundles"

        if not bundles_dir.exists():
            return []

        return [
            d.name
            for d in bundles_dir.iterdir()
            if d.is_dir() and (d / "bundle.enc").exists()
        ]

    except Exception as e:
        logger.warning(f"Failed to list cached bundles: {e}")
        return []


def clear_bundle_cache(bundle_id: str) -> bool:
    """Remove a specific bundle from cache.

    Args:
        bundle_id: Bundle to remove

    Returns:
        True if successfully removed
    """
    try:
        cache_dir = get_cache_dir()
        bundle_path = cache_dir / "bundles" / bundle_id

        if bundle_path.exists():
            import shutil
            shutil.rmtree(bundle_path)
            logger.debug(f"Cleared cache for bundle {bundle_id}")
            return True
        return False

    except Exception as e:
        logger.warning(f"Failed to clear cache for {bundle_id}: {e}")
        return False


def clear_expired_cache() -> int:
    """Remove all expired cached bundles.

    Returns:
        Number of bundles removed
    """
    removed = 0
    now = datetime.now(timezone.utc)

    for bundle_id in list_cached_bundles():
        try:
            cache_dir = get_cache_dir()
            license_file = cache_dir / "bundles" / bundle_id / "license.json"

            if license_file.exists():
                license_data = json.loads(license_file.read_text())
                expires_at_str = license_data.get("expires_at")

                if expires_at_str:
                    expires_at = datetime.fromisoformat(
                        expires_at_str.replace("Z", "+00:00")
                    )
                    if now > expires_at:
                        if clear_bundle_cache(bundle_id):
                            removed += 1
                            logger.info(f"Removed expired cache for {bundle_id}")

        except Exception as e:
            logger.warning(f"Error checking expiration for {bundle_id}: {e}")

    return removed


def get_cache_stats() -> dict[str, Any]:
    """Get statistics about the cache.

    Returns:
        Dict with cache statistics
    """
    try:
        cache_dir = get_cache_dir()
        bundles_dir = cache_dir / "bundles"

        if not bundles_dir.exists():
            return {
                "cache_dir": str(cache_dir),
                "total_bundles": 0,
                "total_size_bytes": 0,
                "expired_bundles": 0,
            }

        total_bundles = 0
        total_size = 0
        expired_bundles = 0
        now = datetime.now(timezone.utc)

        for bundle_dir in bundles_dir.iterdir():
            if not bundle_dir.is_dir():
                continue

            total_bundles += 1

            # Sum up file sizes
            for f in bundle_dir.iterdir():
                if f.is_file():
                    total_size += f.stat().st_size

            # Check expiration
            license_file = bundle_dir / "license.json"
            if license_file.exists():
                try:
                    license_data = json.loads(license_file.read_text())
                    expires_at_str = license_data.get("expires_at")
                    if expires_at_str:
                        expires_at = datetime.fromisoformat(
                            expires_at_str.replace("Z", "+00:00")
                        )
                        if now > expires_at:
                            expired_bundles += 1
                except Exception:
                    pass

        return {
            "cache_dir": str(cache_dir),
            "total_bundles": total_bundles,
            "total_size_bytes": total_size,
            "expired_bundles": expired_bundles,
        }

    except Exception as e:
        logger.warning(f"Failed to get cache stats: {e}")
        return {"error": str(e)}
