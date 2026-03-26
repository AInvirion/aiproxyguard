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

"""Tests for the manifest verifier."""

from __future__ import annotations

import base64
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aiproxyguard.signatures.verifier import (
    ManifestVerifier,
    VerificationResult,
    get_verifier,
    init_verifier,
)


def generate_test_keypair():
    """Generate a test Ed25519 keypair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes_raw()
    return private_key, base64.b64encode(public_key_bytes).decode()


def sign_manifest(private_key: Ed25519PrivateKey, manifest_data: dict) -> str:
    """Sign a manifest with the given private key."""
    sign_payload = {
        "version": manifest_data.get("version", ""),
        "bundles": manifest_data.get("bundles", []),
        "sequence": manifest_data.get("sequence", 0),
        "previous_hash": manifest_data.get("previous_hash", ""),
    }
    canonical = json.dumps(sign_payload, sort_keys=True, separators=(",", ":"))
    signature = private_key.sign(canonical.encode("utf-8"))
    return base64.b64encode(signature).decode()


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_valid_result(self):
        """Valid result should have valid=True."""
        result = VerificationResult(valid=True, sequence=5)
        assert result.valid is True
        assert result.error is None
        assert result.sequence == 5

    def test_invalid_result_with_error(self):
        """Invalid result should have error message."""
        result = VerificationResult(valid=False, error="Test error", sequence=0)
        assert result.valid is False
        assert result.error == "Test error"


class TestManifestVerifier:
    """Tests for ManifestVerifier."""

    def test_init_with_valid_key(self):
        """Verifier should initialize with valid public key."""
        _, public_key_b64 = generate_test_keypair()
        verifier = ManifestVerifier(public_key_b64)

        assert verifier.enabled is True

    def test_init_with_invalid_key(self):
        """Verifier should handle invalid public key gracefully."""
        verifier = ManifestVerifier("not-valid-base64!")

        # Should not crash, but may be disabled
        assert verifier._public_key_bytes is None or verifier.enabled is False

    def test_init_with_env_var(self):
        """Verifier should fall back to env var."""
        _, public_key_b64 = generate_test_keypair()
        os.environ["AIPROXYGUARD_MANIFEST_PUBLIC_KEY"] = public_key_b64

        try:
            verifier = ManifestVerifier()
            assert verifier.enabled is True
        finally:
            del os.environ["AIPROXYGUARD_MANIFEST_PUBLIC_KEY"]

    def test_verify_manifest_missing_signature(self):
        """Manifest without signature should be rejected."""
        _, public_key_b64 = generate_test_keypair()
        verifier = ManifestVerifier(public_key_b64)

        manifest = {
            "version": "1.0.0",
            "bundles": [],
            "sequence": 1,
            "previous_hash": "",
            # No signature
        }

        result = verifier.verify_manifest(manifest)

        assert result.valid is False
        assert "missing signature" in result.error.lower()

    def test_verify_manifest_valid_signature(self):
        """Manifest with valid signature should pass."""
        private_key, public_key_b64 = generate_test_keypair()
        verifier = ManifestVerifier(public_key_b64)

        manifest = {
            "version": "1.0.0",
            "bundles": [{"id": "test-bundle"}],
            "sequence": 1,
            "previous_hash": "",
        }
        manifest["signature"] = sign_manifest(private_key, manifest)

        result = verifier.verify_manifest(manifest)

        assert result.valid is True
        assert result.sequence == 1

    def test_verify_manifest_invalid_signature(self):
        """Manifest with invalid signature should fail."""
        _, public_key_b64 = generate_test_keypair()
        verifier = ManifestVerifier(public_key_b64)

        manifest = {
            "version": "1.0.0",
            "bundles": [],
            "sequence": 1,
            "previous_hash": "",
            "signature": base64.b64encode(b"invalid-signature-data").decode(),
        }

        result = verifier.verify_manifest(manifest)

        assert result.valid is False
        assert "verification failed" in result.error.lower()

    def test_verify_manifest_rollback_protection(self):
        """Verifier should reject sequence rollback."""
        private_key, public_key_b64 = generate_test_keypair()
        verifier = ManifestVerifier(public_key_b64)

        # First manifest with sequence 5
        manifest1 = {
            "version": "1.0.0",
            "bundles": [],
            "sequence": 5,
            "previous_hash": "",
        }
        manifest1["signature"] = sign_manifest(private_key, manifest1)
        result1 = verifier.verify_manifest(manifest1)
        assert result1.valid is True

        # Second manifest with lower sequence should fail
        manifest2 = {
            "version": "1.0.1",
            "bundles": [],
            "sequence": 3,  # Rollback attempt
            "previous_hash": "",
        }
        manifest2["signature"] = sign_manifest(private_key, manifest2)
        result2 = verifier.verify_manifest(manifest2)

        assert result2.valid is False
        assert "rollback" in result2.error.lower()

    def test_verify_manifest_chain_integrity(self):
        """Verifier should check previous_hash chain."""
        private_key, public_key_b64 = generate_test_keypair()
        verifier = ManifestVerifier(public_key_b64)

        # First manifest
        manifest1 = {
            "version": "1.0.0",
            "bundles": [],
            "sequence": 1,
            "previous_hash": "",
        }
        manifest1["signature"] = sign_manifest(private_key, manifest1)
        result1 = verifier.verify_manifest(manifest1)
        assert result1.valid is True

        # Second manifest with wrong previous_hash
        manifest2 = {
            "version": "1.0.1",
            "bundles": [],
            "sequence": 2,
            "previous_hash": "wrong-hash-value",
        }
        manifest2["signature"] = sign_manifest(private_key, manifest2)
        result2 = verifier.verify_manifest(manifest2)

        assert result2.valid is False
        assert "chain" in result2.error.lower() or "previous_hash" in result2.error.lower()

    def test_reset_state(self):
        """reset_state should clear sequence tracking."""
        private_key, public_key_b64 = generate_test_keypair()
        verifier = ManifestVerifier(public_key_b64)

        # First manifest with high sequence
        manifest1 = {
            "version": "1.0.0",
            "bundles": [],
            "sequence": 100,
            "previous_hash": "",
        }
        manifest1["signature"] = sign_manifest(private_key, manifest1)
        verifier.verify_manifest(manifest1)

        # Reset state
        verifier.reset_state()

        # Now lower sequence should be accepted
        manifest2 = {
            "version": "1.0.1",
            "bundles": [],
            "sequence": 1,
            "previous_hash": "",
        }
        manifest2["signature"] = sign_manifest(private_key, manifest2)
        result = verifier.verify_manifest(manifest2)

        assert result.valid is True

    def test_compute_manifest_hash(self):
        """Hash computation should be deterministic."""
        _, public_key_b64 = generate_test_keypair()
        verifier = ManifestVerifier(public_key_b64)

        manifest_data = {
            "version": "1.0.0",
            "bundles": [{"id": "test"}],
            "sequence": 1,
            "previous_hash": "",
        }

        hash1 = verifier._compute_manifest_hash(manifest_data)
        hash2 = verifier._compute_manifest_hash(manifest_data)

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex


class TestGlobalVerifier:
    """Tests for global verifier functions."""

    def test_get_verifier_returns_instance(self):
        """get_verifier should return a ManifestVerifier instance."""
        verifier = get_verifier()
        assert isinstance(verifier, ManifestVerifier)

    def test_init_verifier_with_custom_key(self):
        """init_verifier should create verifier with custom key."""
        _, public_key_b64 = generate_test_keypair()
        verifier = init_verifier(public_key_b64)

        assert isinstance(verifier, ManifestVerifier)
        assert verifier.enabled is True

    def test_get_verifier_returns_same_instance(self):
        """get_verifier should return the same instance."""
        # Reset global state first
        import aiproxyguard.signatures.verifier as verifier_module

        verifier_module._verifier = None

        v1 = get_verifier()
        v2 = get_verifier()

        assert v1 is v2
