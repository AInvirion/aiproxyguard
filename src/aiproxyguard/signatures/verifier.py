"""Ed25519 signature verification for manifest integrity."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Default public key (base64-encoded Ed25519 public key)
# This should be replaced with the actual production public key
DEFAULT_PUBLIC_KEY = ""


@dataclass
class VerificationResult:
    """Result of manifest verification."""

    valid: bool
    error: str | None = None
    sequence: int = 0


class ManifestVerifier:
    """Verifies Ed25519 signatures on signature manifests.

    The verifier tracks sequence numbers to prevent rollback attacks
    and verifies the chain of manifests via previous_hash.
    """

    def __init__(self, public_key: str | None = None):
        """Initialize the verifier.

        Args:
            public_key: Base64-encoded Ed25519 public key. If not provided,
                       falls back to AIPROXYGUARD_MANIFEST_PUBLIC_KEY env var
                       or the embedded default key.
        """
        self._public_key_bytes: bytes | None = None
        self._last_sequence: int = 0
        self._last_manifest_hash: str = ""

        # Resolve the public key
        key_b64 = public_key or os.environ.get(
            "AIPROXYGUARD_MANIFEST_PUBLIC_KEY", DEFAULT_PUBLIC_KEY
        )
        if key_b64:
            try:
                self._public_key_bytes = base64.b64decode(key_b64)
            except Exception as e:
                logger.warning(f"Failed to decode public key: {e}")

    @property
    def enabled(self) -> bool:
        """Whether signature verification is enabled."""
        return self._public_key_bytes is not None

    def _get_public_key(self):
        """Get the Ed25519 public key object."""
        if not self._public_key_bytes:
            return None
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            return Ed25519PublicKey.from_public_bytes(self._public_key_bytes)
        except Exception as e:
            logger.error(f"Failed to load public key: {e}")
            return None

    def verify_manifest(self, manifest_data: dict) -> VerificationResult:
        """Verify a manifest's signature and chain integrity.

        Args:
            manifest_data: The manifest dict as returned by the control plane.

        Returns:
            VerificationResult indicating whether verification passed.
        """
        # Extract fields
        version = manifest_data.get("version", "")
        bundles = manifest_data.get("bundles", [])
        sequence = manifest_data.get("sequence", 0)
        previous_hash = manifest_data.get("previous_hash", "")
        signature_b64 = manifest_data.get("signature", "")

        # If no signature is present and verification is enabled, that's an error
        if not signature_b64:
            if self.enabled:
                return VerificationResult(
                    valid=False,
                    error="Manifest missing signature",
                    sequence=sequence,
                )
            # Verification not enabled, allow unsigned manifests
            logger.debug("Signature verification disabled, accepting unsigned manifest")
            return VerificationResult(valid=True, sequence=sequence)

        # Check sequence number (anti-rollback)
        if sequence < self._last_sequence:
            return VerificationResult(
                valid=False,
                error=f"Sequence rollback detected: {sequence} < {self._last_sequence}",
                sequence=sequence,
            )

        # Check chain integrity if we have a previous hash
        if self._last_manifest_hash and previous_hash:
            if previous_hash != self._last_manifest_hash:
                return VerificationResult(
                    valid=False,
                    error=f"Chain verification failed: previous_hash mismatch",
                    sequence=sequence,
                )

        # Verify the cryptographic signature
        public_key = self._get_public_key()
        if not public_key:
            if self.enabled:
                return VerificationResult(
                    valid=False,
                    error="Public key not available for verification",
                    sequence=sequence,
                )
            # If not enabled, allow the manifest
            return VerificationResult(valid=True, sequence=sequence)

        try:
            # Reconstruct the canonical payload that was signed
            sign_payload = {
                "version": version,
                "bundles": bundles,
                "sequence": sequence,
                "previous_hash": previous_hash,
            }
            canonical = json.dumps(sign_payload, sort_keys=True, separators=(",", ":"))
            signature = base64.b64decode(signature_b64)

            # Verify the signature
            public_key.verify(signature, canonical.encode("utf-8"))

            # Signature valid - update tracking state
            self._last_sequence = sequence
            self._last_manifest_hash = self._compute_manifest_hash(sign_payload)

            logger.debug(f"Manifest signature verified (sequence={sequence})")
            return VerificationResult(valid=True, sequence=sequence)

        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return VerificationResult(
                valid=False,
                error=f"Signature verification failed: {e}",
                sequence=sequence,
            )

    def _compute_manifest_hash(self, manifest_data: dict) -> str:
        """Compute SHA-256 hash of manifest data for chain verification."""
        canonical = json.dumps(manifest_data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def reset_state(self) -> None:
        """Reset the verifier state (for testing or recovery)."""
        self._last_sequence = 0
        self._last_manifest_hash = ""


# Global verifier instance
_verifier: ManifestVerifier | None = None


def get_verifier() -> ManifestVerifier:
    """Get the global manifest verifier instance."""
    global _verifier
    if _verifier is None:
        _verifier = ManifestVerifier()
    return _verifier


def init_verifier(public_key: str | None = None) -> ManifestVerifier:
    """Initialize the global manifest verifier with a specific public key."""
    global _verifier
    _verifier = ManifestVerifier(public_key)
    return _verifier
