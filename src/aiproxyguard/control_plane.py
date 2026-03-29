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

"""Control plane client for fleet management, signature sync, and telemetry."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable

import httpx

from aiproxyguard.signatures.verifier import ManifestVerifier, get_verifier

if TYPE_CHECKING:
    from aiproxyguard.config import ControlPlaneConfig
    from aiproxyguard.crypto.license import License
    from aiproxyguard.signatures.bundle import SignatureBundleSet
    from aiproxyguard.signatures.models import SignatureSet

logger = logging.getLogger(__name__)


def _get_instance_id() -> str:
    """Generate a stable instance ID based on machine characteristics."""
    # Combine hostname and MAC-like identifier for stability across restarts
    hostname = platform.node()
    machine = platform.machine()
    system = platform.system()
    unique_str = f"{hostname}-{machine}-{system}"
    return hashlib.sha256(unique_str.encode()).hexdigest()[:32]


def _get_fingerprint() -> str:
    """Generate a fingerprint of the current environment."""
    info = {
        "python": platform.python_version(),
        "os": platform.system(),
        "arch": platform.machine(),
        "hostname": platform.node(),
    }
    fingerprint_str = "|".join(f"{k}={v}" for k, v in sorted(info.items()))
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]


@dataclass
class TelemetryEvent:
    """A detection event to report to the control plane."""

    event_type: str  # "detection", "block", "allow"
    category: str  # "prompt_injection", "jailbreak", etc.
    signature_id: str | None = None
    latency_ms: int | None = None
    provider: str | None = None  # "ollama", "openai", "anthropic", etc.
    endpoint: str | None = None  # "/api/chat", "/v1/completions", etc.
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ControlPlaneClient:
    """Client for communicating with the AIProxyGuard control plane."""

    def __init__(
        self,
        config: ControlPlaneConfig,
        version: str = "0.1.0",
        manifest_verifier: ManifestVerifier | None = None,
    ):
        self.config = config
        self.version = version
        self.instance_id = _get_instance_id()
        self.fingerprint = _get_fingerprint()
        self._client: httpx.AsyncClient | None = None
        self._heartbeat_task: asyncio.Task | None = None
        self._telemetry_buffer: list[TelemetryEvent] = []
        self._telemetry_lock = asyncio.Lock()
        self._registered: bool = False  # Only enable telemetry after successful registration
        self._auth_permanently_failed: bool = False  # Stop retrying on 401/403
        self._last_config_version: int = 0
        self._last_signature_version: str = ""
        self._last_ml_model_version: str = ""
        self._tier: str = "free"  # Updated from heartbeat response
        self._policy_update_callback: Callable[[dict], None] | None = None
        self._signature_update_callback: Callable[[SignatureSet], None] | None = None
        self._ml_model_callback: Callable[[bytes, dict], None] | None = None
        self._logging_update_callback: Callable[[dict], None] | None = None
        self._scanner_update_callback: Callable[[dict], None] | None = None
        self._ml_config_update_callback: Callable[[dict], None] | None = None
        self._security_update_callback: Callable[[dict], None] | None = None
        self._manifest_verifier = manifest_verifier or get_verifier()
        self._cached_license: dict | None = None
        self._cached_license_model_id: str | None = None
        # Signature bundle tracking
        self._bundle_licenses: dict[str, dict] = {}  # bundle_id -> license_data
        self._bundle_set: SignatureBundleSet | None = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.url,
                headers={
                    "X-API-Key": self.config.api_key,
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
        return self._client

    def set_policy_update_callback(self, callback: Callable[[dict], None]) -> None:
        """Set callback for policy updates.

        The callback will be invoked with the new policy config dict
        whenever a policy update is detected.
        """
        self._policy_update_callback = callback

    def set_signature_update_callback(
        self, callback: Callable[[SignatureSet], None]
    ) -> None:
        """Set callback for signature updates.

        The callback will be invoked with a new SignatureSet whenever
        new signatures are downloaded from the control plane.
        """
        self._signature_update_callback = callback

    def set_ml_model_callback(
        self, callback: Callable[[bytes, dict], None]
    ) -> None:
        """Set callback for ML model updates.

        The callback will be invoked with (decrypted_model_bytes, license_data)
        whenever a new ML model is downloaded and decrypted.
        """
        self._ml_model_callback = callback

    def set_logging_update_callback(self, callback: Callable[[dict], None]) -> None:
        """Set callback for logging config updates.

        The callback will be invoked with logging config dict containing:
        - level: Log level (debug, info, warning, error)
        - format: Log format (json, text)
        - redact_keys: Whether to redact sensitive keys
        """
        self._logging_update_callback = callback

    def set_scanner_update_callback(self, callback: Callable[[dict], None]) -> None:
        """Set callback for scanner config updates.

        The callback will be invoked with scanner config dict containing:
        - enabled: Master enable/disable
        - regex: Enable regex scanning
        - heuristics: Enable heuristics scanning
        - ml_classifier: Enable ML classifier
        """
        self._scanner_update_callback = callback

    def set_ml_config_update_callback(self, callback: Callable[[dict], None]) -> None:
        """Set callback for ML classifier config updates.

        The callback will be invoked with ML config dict containing:
        - threshold: Confidence threshold (0.0-1.0)
        - action: Action on detection (block, warn, log)
        """
        self._ml_config_update_callback = callback

    def set_security_update_callback(self, callback: Callable[[dict], None]) -> None:
        """Set callback for security config updates.

        The callback will be invoked with security config dict containing:
        - failure_mode: Failure mode (open, closed)
        - scanner_timeout_ms: Scanner timeout in milliseconds
        """
        self._security_update_callback = callback

    def set_initial_signature_version(self, version: str) -> None:
        """Set the initial signature version from bundled signatures.

        This prevents misleading '' -> 'vX.X.X' log messages on first sync.
        """
        if version:
            self._last_signature_version = version
            logger.debug(f"Initial signature version set to {version}")

    async def start(self) -> None:
        """Start the control plane client (register and begin heartbeat)."""
        if not self.config.enabled:
            logger.info("Control plane disabled, skipping")
            return

        if not self.config.url or not self.config.url.startswith(("http://", "https://")):
            logger.warning("Control plane URL not configured, skipping")
            return

        logger.info(f"Connecting to control plane at {self.config.url}")
        # Attempt initial registration with retry
        await self._register_with_retry()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("Control plane client started")

    async def _register_with_retry(self, max_attempts: int = 3) -> None:
        """Attempt registration with exponential backoff."""
        base_delay = 1.0
        for attempt in range(max_attempts):
            await self._register()
            if self._registered:
                return
            # Stop immediately on permanent auth failure (invalid/revoked key)
            if self._auth_permanently_failed:
                return
            # Exponential backoff: 1s, 2s, 4s
            delay = base_delay * (2 ** attempt)
            logger.info(f"Registration failed, retrying in {delay}s (attempt {attempt + 1}/{max_attempts})")
            await asyncio.sleep(delay)
        if not self._auth_permanently_failed:
            logger.warning("Initial registration failed after retries; will retry in heartbeat loop")

    async def stop(self) -> None:
        """Stop the control plane client."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        # Flush any remaining telemetry
        await self._flush_telemetry()

        if self._client:
            await self._client.aclose()
            self._client = None

    async def _register(self) -> None:
        """Register this instance with the fleet."""
        try:
            response = await self.client.post(
                "/api/v1/fleet/register",
                json={
                    "instance_id": self.instance_id,
                    "fingerprint": self.fingerprint,
                    "version": self.version,
                    "name": platform.node(),
                    "metadata": {
                        "os": platform.system(),
                        "arch": platform.machine(),
                        "python": platform.python_version(),
                    },
                },
            )
            response.raise_for_status()
            self._registered = True
            self._auth_permanently_failed = False  # Clear any previous auth failure
            logger.info(f"Registered with control plane as {self.instance_id}")
        except httpx.HTTPStatusError as e:
            # Check for permanent auth failures (invalid/revoked API key)
            if e.response.status_code in (401, 403):
                self._auth_permanently_failed = True
                logger.error(
                    "API key invalid or revoked. Control plane features disabled. "
                    "Update your API key in the config and restart the proxy."
                )
            else:
                logger.error(f"Failed to register with control plane: {e}")
        except httpx.HTTPError as e:
            logger.error(f"Failed to register with control plane: {e}")
            # Telemetry stays disabled until registration succeeds

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to the control plane."""
        while True:
            try:
                # Exit loop if auth permanently failed (invalid/revoked API key)
                if self._auth_permanently_failed:
                    logger.info(
                        "Heartbeat loop stopped due to invalid API key. "
                        "Proxy continues in offline mode."
                    )
                    break

                await asyncio.sleep(self.config.heartbeat_interval)

                # Retry registration if not yet registered
                if not self._registered:
                    await self._register()
                    if self._registered:
                        logger.info("Registration succeeded on retry")
                    elif self._auth_permanently_failed:
                        continue  # Will exit on next iteration

                await self._send_heartbeat()
                await self._flush_telemetry()
            except asyncio.CancelledError:
                logger.debug("Heartbeat loop cancelled")
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}", exc_info=True)

    async def _send_heartbeat(self) -> None:
        """Send a heartbeat to the control plane."""
        try:
            response = await self.client.post(
                f"/api/v1/fleet/heartbeat/{self.instance_id}",
                json={
                    "instance_id": self.instance_id,
                    "version": self.version,
                    "config_version": self._last_config_version,
                    "signature_version": self._last_signature_version,
                    "metadata": {
                        "os": platform.system(),
                        "arch": platform.machine(),
                    },
                },
            )
            response.raise_for_status()
            data = response.json()
            logger.debug("Heartbeat sent successfully")

            # Update tier from heartbeat response
            new_tier = data.get("tier", "free")
            if new_tier != self._tier:
                logger.info(f"Account tier changed: {self._tier} -> {new_tier}")
                self._tier = new_tier
                # Sync ML model when tier changes (e.g., upgrade to enterprise)
                if self._ml_model_callback:
                    await self.sync_ml_model()

            # Check if config version changed
            server_config_version = data.get("config_version", 0)
            if server_config_version > self._last_config_version:
                logger.info(
                    f"Config version changed: {self._last_config_version} -> {server_config_version}"
                )
                await self._fetch_and_apply_policy()
                self._last_config_version = server_config_version

            # Check if signature version changed
            server_signature_version = data.get("signature_version", "")
            if (
                server_signature_version
                and server_signature_version != self._last_signature_version
            ):
                logger.info(
                    f"Signature version changed: {self._last_signature_version!r} -> {server_signature_version!r}"
                )
                await self._fetch_and_apply_signatures()
            else:
                # Check for expiring licenses even if signature version unchanged
                await self._refresh_expiring_licenses()

        except httpx.HTTPStatusError as e:
            # Check for permanent auth failures (API key revoked while running)
            if e.response.status_code in (401, 403):
                self._auth_permanently_failed = True
                logger.error(
                    "API key invalid or revoked. Control plane features disabled. "
                    "Update your API key in the config and restart the proxy."
                )
            else:
                logger.warning(f"Heartbeat failed: {e}")
        except httpx.HTTPError as e:
            logger.warning(f"Heartbeat failed: {e}")

    async def _refresh_expiring_licenses(self) -> None:
        """Check for licenses expiring within 24 hours and refresh them.

        This ensures the proxy always has valid licenses for encrypted bundles,
        even if the signature version hasn't changed. On restart, the proxy
        can still decrypt cached bundles with refreshed licenses.
        """
        from datetime import datetime, timedelta, timezone

        if not self._bundle_licenses:
            return

        now = datetime.now(timezone.utc)
        refresh_threshold = timedelta(hours=24)

        for bundle_id, license_data in list(self._bundle_licenses.items()):
            expires_at_str = license_data.get("expires_at")
            if not expires_at_str:
                continue

            try:
                # Parse expiration timestamp
                expires_at = datetime.fromisoformat(
                    expires_at_str.replace("Z", "+00:00")
                )
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)

                time_remaining = expires_at - now

                if time_remaining < refresh_threshold:
                    hours_remaining = time_remaining.total_seconds() / 3600
                    logger.info(
                        f"License for bundle {bundle_id} expires in {hours_remaining:.1f} hours, refreshing..."
                    )

                    # Fetch new license
                    try:
                        response = await self.client.get(
                            f"/api/v1/signatures/licenses/bundle/{bundle_id}"
                        )
                        response.raise_for_status()
                        new_license = response.json()

                        # Update cached license
                        self._bundle_licenses[bundle_id] = new_license

                        # Update cache file if caching is enabled
                        from aiproxyguard.signatures.cache import save_bundle_license
                        save_bundle_license(bundle_id, new_license)

                        new_expires = new_license.get("expires_at", "unknown")
                        logger.info(
                            f"Refreshed license for bundle {bundle_id}, "
                            f"new expiration: {new_expires}"
                        )
                    except Exception as e:
                        logger.warning(f"Failed to refresh license for {bundle_id}: {e}")

            except Exception as e:
                logger.debug(f"Error checking license expiration for {bundle_id}: {e}")

    async def _fetch_and_apply_policy(self) -> None:
        """Fetch active policy from control plane and apply all config sections."""
        try:
            # Pass instance_id to get instance-specific policy
            response = await self.client.get(
                "/api/v1/fleet/policies/active",
                params={"instance_id": self.instance_id},
            )
            response.raise_for_status()
            policy_data = response.json()

            logger.info(
                f"Fetched policy '{policy_data.get('name')}' version {policy_data.get('version')}"
            )

            config = policy_data.get("config", {})

            # Apply policy/detection settings
            if self._policy_update_callback:
                translated = self._translate_policy_config(config)
                self._policy_update_callback(translated)
                logger.info("Policy engine updated with new config")

            # Apply logging settings
            logging_config = config.get("logging")
            if logging_config and self._logging_update_callback:
                self._logging_update_callback(logging_config)
                logger.info(
                    "Logging config updated",
                    extra={"config": logging_config},
                )

            # Apply scanner settings
            scanner_config = config.get("scanner")
            if scanner_config and self._scanner_update_callback:
                self._scanner_update_callback(scanner_config)
                logger.info(
                    "Scanner config updated",
                    extra={"config": scanner_config},
                )

            # Apply ML classifier settings
            ml_config = config.get("ml_classifier")
            if ml_config and self._ml_config_update_callback:
                self._ml_config_update_callback(ml_config)
                logger.info(
                    "ML classifier config updated",
                    extra={"config": ml_config},
                )

            # Apply security settings
            security_config = config.get("security")
            if security_config and self._security_update_callback:
                self._security_update_callback(security_config)
                logger.info(
                    "Security config updated",
                    extra={"config": security_config},
                )

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch active policy: {e}")

    def _translate_policy_config(self, cloud_config: dict) -> dict:
        """Translate cloud policy config to PolicyEngine format.

        Cloud format:
            {
                "detection": {
                    "prompt_injection": {"enabled": true, "action": "warn", "threshold": 0.7},
                    ...
                },
                "logging": {...}
            }

        PolicyEngine format:
            {
                "default_action": "block",
                "categories": {
                    "prompt_injection": {"action": "warn", "threshold": 0.7},
                    ...
                },
                "allowlists": [...]
            }
        """
        detection = cloud_config.get("detection", {})
        categories = {}

        # Infer default action from the most common action or use "block"
        actions = [cat.get("action", "block") for cat in detection.values() if cat.get("enabled", True)]
        default_action = max(set(actions), key=actions.count) if actions else "block"

        for category, cat_config in detection.items():
            if cat_config.get("enabled", True):
                categories[category] = {
                    "action": cat_config.get("action", default_action),
                    "threshold": cat_config.get("threshold", 0.5),
                }

        return {
            "default_action": default_action,
            "categories": categories,
            "allowlists": cloud_config.get("allowlists", []),
        }

    async def _fetch_and_apply_signatures(self) -> None:
        """Fetch new signatures from control plane and hot-reload them.

        Supports both plain (free tier) and encrypted (paid tier) bundles.
        Falls back to cached bundles if network is unavailable.
        """
        if not self.config.sync_signatures:
            logger.debug("Signature sync disabled, skipping signature update")
            return

        from aiproxyguard.signatures.cache import (
            clear_expired_cache,
            load_bundle_cache,
            save_bundle_cache,
        )
        from aiproxyguard.signatures.loader import parse_bundles_to_bundle_set

        # Clean up expired cache entries periodically
        clear_expired_cache()

        try:
            # Fetch the signature manifest for the account's tier
            response = await self.client.get(
                "/api/v1/signatures/manifest",
                params={"tier": self._tier},
            )
            response.raise_for_status()
            manifest_data = response.json()

            # Verify manifest signature and chain integrity
            verification = self._manifest_verifier.verify_manifest(manifest_data)
            if not verification.valid:
                logger.error(
                    f"Manifest verification failed: {verification.error}"
                )
                return

            manifest_version = manifest_data.get("version", "")
            bundles = manifest_data.get("bundles", [])

            if not bundles:
                logger.warning("No signature bundles in manifest")
                return

            logger.info(
                f"Fetched signature manifest version {manifest_version} "
                f"(sequence={verification.sequence}) with {len(bundles)} bundles"
            )

            # Fetch each bundle's content (with encryption support)
            bundle_contents = []
            licenses: dict[str, License] = {}

            for bundle_info in bundles:
                bundle_id = bundle_info.get("id")
                if not bundle_id:
                    continue

                is_encrypted = bundle_info.get("is_encrypted", False)
                tier = bundle_info.get("tier", "free")

                if is_encrypted:
                    # Fetch encrypted bundle with license
                    result = await self._fetch_encrypted_bundle(
                        bundle_id, bundle_info, load_bundle_cache, save_bundle_cache
                    )
                    if result:
                        bundle_contents.append(result["content_info"])
                        if result.get("license"):
                            licenses[bundle_id] = result["license"]
                else:
                    # Plain bundle (free tier)
                    try:
                        bundle_response = await self.client.get(
                            f"/api/v1/signatures/bundles/{bundle_id}"
                        )
                        bundle_response.raise_for_status()
                        bundle_data = bundle_response.json()
                        bundle_contents.append({
                            "bundle_id": bundle_id,
                            "version": bundle_info.get("version", ""),
                            "tier": tier,
                            "content": bundle_data.get("content", ""),
                            "is_encrypted": False,
                        })
                        logger.debug(f"Fetched plain bundle {bundle_id}")
                    except httpx.HTTPError as e:
                        logger.warning(f"Failed to fetch bundle {bundle_id}: {e}")

            if not bundle_contents:
                logger.warning("No bundle contents fetched")
                return

            # Parse into SignatureBundleSet with expiration tracking
            self._bundle_set = parse_bundles_to_bundle_set(bundle_contents, licenses)
            self._bundle_licenses = {bid: lic.__dict__ for bid, lic in licenses.items()}

            # Get active (non-expired) signatures
            active_signatures = self._bundle_set.get_active_signatures()

            logger.info(
                f"Parsed {self._bundle_set.total_signatures} signatures from "
                f"{len(bundle_contents)} bundles "
                f"({self._bundle_set.active_signatures_count} active)"
            )

            # Warn about expiring bundles
            expiring_soon = self._bundle_set.get_expiring_soon(within_hours=24)
            for bundle in expiring_soon:
                logger.warning(
                    f"Bundle {bundle.bundle_id} expires in "
                    f"{bundle.time_until_expiry / 3600:.1f} hours"
                )

            # Apply via callback
            if self._signature_update_callback:
                self._signature_update_callback(active_signatures)
                latest_bundle_version = max(
                    (b.get("version", "") for b in bundle_contents),
                    default=manifest_version,
                )
                self._last_signature_version = latest_bundle_version
                logger.info(
                    f"Scanner reloaded with new signatures (version {latest_bundle_version})"
                )
            else:
                logger.warning("No signature update callback registered")

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch signatures: {e}")
            # Try to load from cache on network failure
            await self._load_signatures_from_cache()
        except Exception as e:
            logger.error(f"Failed to parse/apply signatures: {e}")

    async def _fetch_encrypted_bundle(
        self,
        bundle_id: str,
        bundle_info: dict,
        load_cache_fn,
        save_cache_fn,
    ) -> dict | None:
        """Fetch an encrypted bundle with license, with cache fallback.

        Args:
            bundle_id: Bundle identifier
            bundle_info: Bundle metadata from manifest
            load_cache_fn: Function to load from cache
            save_cache_fn: Function to save to cache

        Returns:
            Dict with 'content_info' and 'license', or None on failure
        """
        from aiproxyguard.crypto.license import (
            decrypt_content,
            is_license_valid,
            parse_license,
        )

        public_key = getattr(self.config, "manifest_public_key", "")

        try:
            # Request license for this bundle
            license_response = await self.client.get(
                f"/api/v1/signatures/licenses/bundle/{bundle_id}"
            )
            license_response.raise_for_status()
            license_data = license_response.json()

            # Verify license
            license = parse_license(license_data)
            valid, reason = is_license_valid(license, public_key, license_data)
            if not valid:
                logger.error(f"Invalid license for {bundle_id}: {reason}")
                return None

            # Download encrypted content
            download_url = license_data.get("download_url")
            if download_url:
                # Download with authentication - follow redirects for http->https
                async with httpx.AsyncClient(
                    timeout=60.0,
                    follow_redirects=True,
                    headers={"X-API-Key": self.config.api_key},
                ) as dl_client:
                    dl_response = await dl_client.get(download_url)
                    dl_response.raise_for_status()
                    encrypted_bytes = dl_response.content
            else:
                # Fallback to API endpoint
                content_response = await self.client.get(
                    f"/api/v1/signatures/bundles/{bundle_id}/content"
                )
                content_response.raise_for_status()
                encrypted_bytes = content_response.content

            # Decrypt
            decrypted = decrypt_content(
                encrypted_bytes,
                license.dek,
                "aiproxyguard-encrypted-bundle-v1",
            )

            # Cache for offline use
            save_cache_fn(bundle_id, encrypted_bytes, license_data)

            logger.debug(f"Fetched encrypted bundle {bundle_id}")

            return {
                "license": license,
                "content_info": {
                    "bundle_id": bundle_id,
                    "version": bundle_info.get("version", ""),
                    "tier": bundle_info.get("tier", ""),
                    "content": decrypted.decode("utf-8"),
                    "is_encrypted": True,
                },
            }

        except Exception as e:
            logger.warning(f"Failed to fetch encrypted bundle {bundle_id}: {e}")

            # Try cache fallback
            cached = load_cache_fn(bundle_id)
            if cached:
                encrypted_bytes, license_data = cached
                try:
                    license = parse_license(license_data)
                    decrypted = decrypt_content(
                        encrypted_bytes,
                        license.dek,
                        "aiproxyguard-encrypted-bundle-v1",
                    )
                    logger.info(f"Loaded {bundle_id} from cache (expires {license.expires_at})")
                    return {
                        "license": license,
                        "content_info": {
                            "bundle_id": bundle_id,
                            "version": license_data.get("bundle_version", ""),
                            "tier": bundle_info.get("tier", ""),
                            "content": decrypted.decode("utf-8"),
                            "is_encrypted": True,
                        },
                    }
                except Exception as cache_err:
                    logger.error(f"Failed to load {bundle_id} from cache: {cache_err}")

            return None

    async def _load_signatures_from_cache(self) -> None:
        """Load all signatures from cache (offline mode)."""
        from aiproxyguard.crypto.license import decrypt_content, parse_license
        from aiproxyguard.signatures.cache import list_cached_bundles, load_bundle_cache
        from aiproxyguard.signatures.loader import parse_bundles_to_bundle_set

        cached_ids = list_cached_bundles()
        if not cached_ids:
            logger.warning("No cached bundles available for offline mode")
            return

        bundle_contents = []
        licenses: dict[str, License] = {}

        for bundle_id in cached_ids:
            cached = load_bundle_cache(bundle_id)
            if not cached:
                continue

            encrypted_bytes, license_data = cached
            try:
                license = parse_license(license_data)
                decrypted = decrypt_content(
                    encrypted_bytes,
                    license.dek,
                    "aiproxyguard-encrypted-bundle-v1",
                )
                bundle_contents.append({
                    "bundle_id": bundle_id,
                    "version": license_data.get("bundle_version", ""),
                    "tier": license_data.get("tier", "unknown"),
                    "content": decrypted.decode("utf-8"),
                    "is_encrypted": True,
                })
                licenses[bundle_id] = license
                logger.info(f"Loaded cached bundle {bundle_id}")
            except Exception as e:
                logger.error(f"Failed to decrypt cached bundle {bundle_id}: {e}")

        if bundle_contents:
            self._bundle_set = parse_bundles_to_bundle_set(bundle_contents, licenses)
            active_signatures = self._bundle_set.get_active_signatures()

            if self._signature_update_callback:
                self._signature_update_callback(active_signatures)

            logger.info(
                f"Offline mode: loaded {len(bundle_contents)} bundles "
                f"({self._bundle_set.active_signatures_count} active signatures)"
            )

    async def report_detection(
        self,
        event_type: str,
        category: str,
        signature_id: str | None = None,
        latency_ms: int | None = None,
        provider: str | None = None,
        endpoint: str | None = None,
    ) -> None:
        """Buffer a detection event for reporting."""
        if not self.config.enabled or not self.config.report_telemetry:
            return
        if not self._registered:
            # Don't send telemetry until registration succeeds
            return

        event = TelemetryEvent(
            event_type=event_type,
            category=category,
            signature_id=signature_id,
            latency_ms=latency_ms,
            provider=provider,
            endpoint=endpoint,
        )

        async with self._telemetry_lock:
            self._telemetry_buffer.append(event)

            # Flush if buffer is large
            if len(self._telemetry_buffer) >= 50:
                await self._flush_telemetry_unlocked()

    async def _flush_telemetry(self) -> None:
        """Flush buffered telemetry events."""
        async with self._telemetry_lock:
            await self._flush_telemetry_unlocked()

    async def _flush_telemetry_unlocked(self) -> None:
        """Flush telemetry without acquiring lock (caller must hold lock)."""
        if not self._telemetry_buffer:
            return

        events = self._telemetry_buffer
        self._telemetry_buffer = []

        try:
            response = await self.client.post(
                "/api/v1/telemetry/events",
                json={
                    "events": [
                        {
                            "instance_id": self.instance_id,
                            "timestamp": e.timestamp.isoformat(),
                            "event_type": e.event_type,
                            "category": e.category,
                            "signature_id": e.signature_id,
                            "latency_ms": e.latency_ms,
                            "provider": e.provider,
                            "endpoint": e.endpoint,
                        }
                        for e in events
                    ]
                },
            )
            response.raise_for_status()
            logger.debug(f"Flushed {len(events)} telemetry events")
        except httpx.HTTPError as e:
            logger.warning(f"Failed to flush telemetry: {e}")
            # Re-add events to buffer for retry
            self._telemetry_buffer = events + self._telemetry_buffer

    async def fetch_signatures(self, tier: str = "free") -> list[dict]:
        """Fetch signature manifest from control plane."""
        if not self.config.enabled or not self.config.sync_signatures:
            return []

        try:
            response = await self.client.get(
                "/api/v1/signatures/manifest",
                params={"tier": tier},
            )
            response.raise_for_status()
            data = response.json()
            return data.get("bundles", [])
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch signatures: {e}")
            return []

    async def fetch_latest_ml_model(self, model_type: str = "sklearn") -> dict | None:
        """Fetch latest ML model metadata from control plane."""
        if not self.config.enabled:
            return None

        try:
            response = await self.client.get(
                "/api/ml-models/latest",
                params={"model_type": model_type},
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            # 404 is expected if cloud doesn't have ML model sync yet
            if e.response.status_code == 404:
                logger.debug("ML model sync not available on control plane")
            else:
                logger.error(f"Failed to fetch latest ML model: {e}")
            return None
        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch latest ML model: {e}")
            return None

    async def fetch_ml_model_license(self, model_id: str) -> dict | None:
        """Request a license for an ML model.

        Returns license data including DEK for decryption.
        """
        if not self.config.enabled:
            return None

        try:
            response = await self.client.post(
                f"/api/ml-models/{model_id}/license",
            )
            response.raise_for_status()
            license_data = response.json()
            logger.info(
                f"Obtained license for model {model_id}, "
                f"expires: {license_data.get('expires_at')}"
            )
            return license_data
        except httpx.HTTPError as e:
            logger.error(f"Failed to obtain ML model license: {e}")
            return None

    async def download_ml_model(self, download_url: str) -> bytes | None:
        """Download encrypted ML model file."""
        try:
            # Use a separate client for external downloads
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.get(download_url)
                response.raise_for_status()
                return response.content
        except httpx.HTTPError as e:
            logger.error(f"Failed to download ML model: {e}")
            return None

    async def sync_ml_model(self, model_type: str = "sklearn") -> bool:
        """Sync the latest ML model from control plane.

        Downloads the model, validates license, decrypts, and calls the callback.

        Returns:
            True if sync was successful
        """
        if not self.config.enabled or not self._ml_model_callback:
            return False

        try:
            # Check for latest model
            model_info = await self.fetch_latest_ml_model(model_type)
            if not model_info:
                logger.debug("No ML model available")
                return False

            model_id = model_info.get("model_id")
            model_version = model_info.get("version")
            is_encrypted = model_info.get("is_encrypted", False)
            is_accessible = model_info.get("is_accessible", False)

            if not is_accessible:
                logger.info(
                    f"ML model {model_id} requires higher tier subscription"
                )
                return False

            # Check if we already have this version
            current_version = f"{model_id}:{model_version}"
            if current_version == self._last_ml_model_version:
                logger.debug(f"ML model {current_version} already loaded")
                return True

            logger.info(f"Syncing ML model {model_id} v{model_version}")

            if is_encrypted:
                return await self._sync_encrypted_model(model_id, model_version)
            else:
                return await self._sync_unencrypted_model(model_id)

        except Exception as e:
            logger.error(f"Failed to sync ML model: {e}")
            return False

    async def _sync_encrypted_model(
        self, model_id: str, model_version: str
    ) -> bool:
        """Sync an encrypted ML model."""
        from aiproxyguard.scanner.ml.license import (
            decrypt_model,
            is_license_valid,
            parse_license,
        )

        # Check if we have a valid cached license
        if (
            self._cached_license
            and self._cached_license_model_id == model_id
        ):
            try:
                license = parse_license(self._cached_license)
                public_key = getattr(self.config, "manifest_public_key", "")
                valid, _ = is_license_valid(license, public_key, self._cached_license)
                if valid:
                    logger.debug("Using cached license")
                else:
                    logger.info("Cached license expired, requesting new one")
                    self._cached_license = None
            except Exception:
                self._cached_license = None

        # Request new license if needed
        if not self._cached_license:
            license_data = await self.fetch_ml_model_license(model_id)
            if not license_data:
                return False
            self._cached_license = license_data
            self._cached_license_model_id = model_id

        # Download encrypted model
        download_url = self._cached_license.get("download_url")
        if not download_url:
            logger.error("No download URL in license")
            return False

        encrypted_data = await self.download_ml_model(download_url)
        if not encrypted_data:
            return False

        # Decrypt model
        try:
            license = parse_license(self._cached_license)
            decrypted_data = decrypt_model(encrypted_data, license.dek)
        except Exception as e:
            logger.error(f"Failed to decrypt ML model: {e}")
            self._cached_license = None  # Clear invalid license
            return False

        # Call callback with decrypted model
        self._ml_model_callback(decrypted_data, self._cached_license)
        self._last_ml_model_version = f"{model_id}:{model_version}"
        logger.info(f"ML model {model_id} v{model_version} synced successfully")
        return True

    async def _sync_unencrypted_model(self, model_id: str) -> bool:
        """Sync an unencrypted ML model (direct download).

        SECURITY WARNING: This method downloads and loads unverified bytes.
        It should only be used in development/testing environments.
        Production deployments MUST use encrypted models with license validation.
        """
        logger.warning(
            "SECURITY: Loading unencrypted ML model from network. "
            "This is only safe in trusted development environments. "
            "Use encrypted models with license validation in production."
        )
        try:
            response = await self.client.get(
                f"/api/ml-models/{model_id}/download",
                follow_redirects=True,
            )
            response.raise_for_status()
            model_data = response.content

            # Call callback with model data (no license for unencrypted)
            self._ml_model_callback(model_data, {})
            logger.info(f"ML model {model_id} synced successfully (unencrypted)")
            return True
        except httpx.HTTPError as e:
            logger.error(f"Failed to download ML model: {e}")
            return False

    def clear_ml_license_cache(self) -> None:
        """Clear cached ML model license (forces refresh on next sync)."""
        self._cached_license = None
        self._cached_license_model_id = None
        logger.debug("ML license cache cleared")


# Global client instance
_client: ControlPlaneClient | None = None


def get_client() -> ControlPlaneClient | None:
    """Get the global control plane client."""
    return _client


def init_client(config: ControlPlaneConfig, version: str = "0.1.0") -> ControlPlaneClient:
    """Initialize the global control plane client."""
    global _client
    # Initialize verifier with public key from config if provided
    verifier = None
    if hasattr(config, "manifest_public_key") and config.manifest_public_key:
        from aiproxyguard.signatures.verifier import ManifestVerifier

        verifier = ManifestVerifier(config.manifest_public_key)
    _client = ControlPlaneClient(config, version, manifest_verifier=verifier)
    return _client
