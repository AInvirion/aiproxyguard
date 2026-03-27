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

"""Unit tests for signature bundle module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aiproxyguard.signatures.bundle import SignatureBundle, SignatureBundleSet
from aiproxyguard.signatures.models import Signature, SignatureSet


def _make_signature(sig_id: str, category: str = "test") -> Signature:
    """Create a test signature."""
    return Signature(
        id=sig_id,
        name=f"Test {sig_id}",
        category=category,
        severity="high",
        patterns=[f"pattern_{sig_id}"],
        action="block",
    )


def _make_signature_set(count: int) -> SignatureSet:
    """Create a SignatureSet with the given number of signatures."""
    return SignatureSet(
        signatures=[_make_signature(f"sig_{i}") for i in range(count)]
    )


class TestSignatureBundle:
    """Tests for SignatureBundle class."""

    def test_create_free_bundle(self) -> None:
        """Test creating a free tier bundle."""
        bundle = SignatureBundle(
            bundle_id="sig-free-v1",
            version="2024.03.26",
            tier="free",
            signatures=_make_signature_set(5),
        )

        assert bundle.bundle_id == "sig-free-v1"
        assert bundle.tier == "free"
        assert bundle.is_free
        assert not bundle.is_expired
        assert bundle.expires_at is None
        assert bundle.time_until_expiry is None

    def test_create_paid_bundle_not_expired(self) -> None:
        """Test creating a paid bundle that hasn't expired."""
        future = datetime.now(timezone.utc) + timedelta(days=30)
        bundle = SignatureBundle(
            bundle_id="sig-pro-v1",
            version="2024.03.26",
            tier="pro",
            signatures=_make_signature_set(10),
            expires_at=future,
            is_encrypted=True,
        )

        assert bundle.tier == "pro"
        assert not bundle.is_free
        assert not bundle.is_expired
        assert bundle.expires_at == future
        assert bundle.is_encrypted
        # Should be close to 30 days in seconds
        assert bundle.time_until_expiry is not None
        assert bundle.time_until_expiry > 29 * 24 * 3600

    def test_expired_bundle(self) -> None:
        """Test that expired bundle is detected."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        bundle = SignatureBundle(
            bundle_id="sig-expired",
            version="2024.01.01",
            tier="enterprise",
            signatures=_make_signature_set(3),
            expires_at=past,
        )

        assert bundle.is_expired
        assert bundle.time_until_expiry is not None
        assert bundle.time_until_expiry < 0

    def test_repr(self) -> None:
        """Test string representation."""
        bundle = SignatureBundle(
            bundle_id="sig-test",
            version="1.0",
            tier="pro",
            signatures=_make_signature_set(5),
        )

        repr_str = repr(bundle)
        assert "sig-test" in repr_str
        assert "pro" in repr_str
        assert "active" in repr_str


class TestSignatureBundleSet:
    """Tests for SignatureBundleSet class."""

    def test_empty_bundle_set(self) -> None:
        """Test empty bundle set."""
        bundle_set = SignatureBundleSet()

        assert len(bundle_set.bundles) == 0
        assert bundle_set.total_signatures == 0
        assert bundle_set.active_signatures_count == 0

    def test_get_active_signatures(self) -> None:
        """Test getting active signatures excludes expired."""
        future = datetime.now(timezone.utc) + timedelta(days=30)
        past = datetime.now(timezone.utc) - timedelta(hours=1)

        bundles = [
            SignatureBundle(
                bundle_id="free",
                version="1.0",
                tier="free",
                signatures=_make_signature_set(3),
            ),
            SignatureBundle(
                bundle_id="active-pro",
                version="1.0",
                tier="pro",
                signatures=_make_signature_set(5),
                expires_at=future,
            ),
            SignatureBundle(
                bundle_id="expired",
                version="1.0",
                tier="enterprise",
                signatures=_make_signature_set(7),
                expires_at=past,
            ),
        ]

        bundle_set = SignatureBundleSet(bundles=bundles)

        assert bundle_set.total_signatures == 15  # 3 + 5 + 7
        assert bundle_set.active_signatures_count == 8  # 3 + 5 (expired excluded)

        active = bundle_set.get_active_signatures()
        assert len(active.signatures) == 8

    def test_get_earliest_expiration(self) -> None:
        """Test getting earliest expiration."""
        now = datetime.now(timezone.utc)
        soon = now + timedelta(days=7)
        later = now + timedelta(days=30)

        bundles = [
            SignatureBundle(
                bundle_id="free",
                version="1.0",
                tier="free",
                signatures=_make_signature_set(1),
            ),
            SignatureBundle(
                bundle_id="expires-soon",
                version="1.0",
                tier="pro",
                signatures=_make_signature_set(1),
                expires_at=soon,
            ),
            SignatureBundle(
                bundle_id="expires-later",
                version="1.0",
                tier="enterprise",
                signatures=_make_signature_set(1),
                expires_at=later,
            ),
        ]

        bundle_set = SignatureBundleSet(bundles=bundles)

        earliest = bundle_set.get_earliest_expiration()
        assert earliest == soon

    def test_get_earliest_expiration_all_free(self) -> None:
        """Test earliest expiration when all bundles are free."""
        bundles = [
            SignatureBundle(
                bundle_id="free1",
                version="1.0",
                tier="free",
                signatures=_make_signature_set(1),
            ),
        ]

        bundle_set = SignatureBundleSet(bundles=bundles)

        assert bundle_set.get_earliest_expiration() is None

    def test_get_expiring_soon(self) -> None:
        """Test getting bundles expiring soon."""
        now = datetime.now(timezone.utc)
        bundles = [
            SignatureBundle(
                bundle_id="free",
                version="1.0",
                tier="free",
                signatures=_make_signature_set(1),
            ),
            SignatureBundle(
                bundle_id="expiring-12h",
                version="1.0",
                tier="pro",
                signatures=_make_signature_set(1),
                expires_at=now + timedelta(hours=12),
            ),
            SignatureBundle(
                bundle_id="expiring-48h",
                version="1.0",
                tier="enterprise",
                signatures=_make_signature_set(1),
                expires_at=now + timedelta(hours=48),
            ),
        ]

        bundle_set = SignatureBundleSet(bundles=bundles)

        # Within 24 hours
        expiring = bundle_set.get_expiring_soon(within_hours=24)
        assert len(expiring) == 1
        assert expiring[0].bundle_id == "expiring-12h"

        # Within 72 hours
        expiring = bundle_set.get_expiring_soon(within_hours=72)
        assert len(expiring) == 2

    def test_get_bundle(self) -> None:
        """Test getting specific bundle by ID."""
        bundles = [
            SignatureBundle(
                bundle_id="bundle-a",
                version="1.0",
                tier="free",
                signatures=_make_signature_set(1),
            ),
            SignatureBundle(
                bundle_id="bundle-b",
                version="2.0",
                tier="pro",
                signatures=_make_signature_set(2),
            ),
        ]

        bundle_set = SignatureBundleSet(bundles=bundles)

        assert bundle_set.get_bundle("bundle-a") is not None
        assert bundle_set.get_bundle("bundle-a").version == "1.0"
        assert bundle_set.get_bundle("bundle-b").version == "2.0"
        assert bundle_set.get_bundle("nonexistent") is None

    def test_repr(self) -> None:
        """Test string representation."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        bundles = [
            SignatureBundle(
                bundle_id="active",
                version="1.0",
                tier="free",
                signatures=_make_signature_set(5),
            ),
            SignatureBundle(
                bundle_id="expired",
                version="1.0",
                tier="pro",
                signatures=_make_signature_set(3),
                expires_at=past,
            ),
        ]

        bundle_set = SignatureBundleSet(bundles=bundles)

        repr_str = repr(bundle_set)
        assert "bundles=2" in repr_str
        assert "active=1" in repr_str
        assert "expired=1" in repr_str
