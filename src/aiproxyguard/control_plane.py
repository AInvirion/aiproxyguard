"""Control plane client for fleet management, signature sync, and telemetry."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import platform
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Callable

import httpx

from aiproxyguard.signatures.verifier import ManifestVerifier, get_verifier

if TYPE_CHECKING:
    from aiproxyguard.config import ControlPlaneConfig
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
        self._last_config_version: int = 0
        self._last_signature_version: str = ""
        self._policy_update_callback: Callable[[dict], None] | None = None
        self._signature_update_callback: Callable[[SignatureSet], None] | None = None
        self._manifest_verifier = manifest_verifier or get_verifier()

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

    async def start(self) -> None:
        """Start the control plane client (register and begin heartbeat)."""
        if not self.config.enabled:
            logger.info("Control plane disabled, skipping")
            return

        logger.info(f"Connecting to control plane at {self.config.url}")
        await self._register()
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        logger.info("Control plane client started")

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
            logger.info(f"Registered with control plane as {self.instance_id}")
        except httpx.HTTPError as e:
            logger.error(f"Failed to register with control plane: {e}")
            # Telemetry stays disabled until registration succeeds

    async def _heartbeat_loop(self) -> None:
        """Send periodic heartbeats to the control plane."""
        while True:
            try:
                await asyncio.sleep(self.config.heartbeat_interval)
                await self._send_heartbeat()
                await self._flush_telemetry()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")

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

        except httpx.HTTPError as e:
            logger.warning(f"Heartbeat failed: {e}")

    async def _fetch_and_apply_policy(self) -> None:
        """Fetch active policy from control plane and apply it."""
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

            if self._policy_update_callback:
                config = policy_data.get("config", {})
                # Translate cloud config format to PolicyEngine format
                translated = self._translate_policy_config(config)
                self._policy_update_callback(translated)
                logger.info("Policy engine updated with new config")
            else:
                logger.warning("No policy update callback registered")

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
        """Fetch new signatures from control plane and hot-reload them."""
        if not self.config.sync_signatures:
            logger.debug("Signature sync disabled, skipping signature update")
            return

        try:
            # Fetch the signature manifest
            response = await self.client.get(
                "/api/v1/signatures/manifest",
                params={"tier": "free"},
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

            # Fetch each bundle's content
            bundle_contents = []
            for bundle in bundles:
                bundle_id = bundle.get("id")
                if not bundle_id:
                    continue

                try:
                    bundle_response = await self.client.get(
                        f"/api/v1/signatures/bundles/{bundle_id}"
                    )
                    bundle_response.raise_for_status()
                    bundle_data = bundle_response.json()
                    bundle_contents.append(bundle_data)
                    logger.debug(f"Fetched signature bundle {bundle_id}")
                except httpx.HTTPError as e:
                    logger.warning(f"Failed to fetch bundle {bundle_id}: {e}")

            if not bundle_contents:
                logger.warning("No bundle contents fetched")
                return

            # Parse signatures from bundles
            from aiproxyguard.signatures.loader import parse_signatures_from_bundles

            new_signatures = parse_signatures_from_bundles(bundle_contents)

            logger.info(
                f"Parsed {len(new_signatures.signatures)} signatures from {len(bundle_contents)} bundles"
            )

            # Apply via callback
            if self._signature_update_callback:
                self._signature_update_callback(new_signatures)
                self._last_signature_version = manifest_version
                logger.info(
                    f"Scanner reloaded with new signatures (version {manifest_version})"
                )
            else:
                logger.warning("No signature update callback registered")

        except httpx.HTTPError as e:
            logger.error(f"Failed to fetch signatures: {e}")
        except Exception as e:
            logger.error(f"Failed to parse/apply signatures: {e}")

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
