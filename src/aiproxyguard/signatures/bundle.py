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

"""Signature bundles with licensing and expiration support.

This module provides bundle-level abstractions for signatures that support:
- Expiration tracking (time-bonded signatures)
- Tier-based access control
- Aggregation of multiple bundles into a single SignatureSet
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiproxyguard.signatures.models import SignatureSet

logger = logging.getLogger(__name__)


@dataclass
class SignatureBundle:
    """A bundle of signatures with licensing metadata.

    Attributes:
        bundle_id: Unique identifier for this bundle
        version: Version string of the bundle
        tier: Required subscription tier ("free", "pro", "enterprise")
        signatures: The actual signatures in this bundle
        expires_at: When the license expires (None for free tier)
        is_encrypted: Whether this bundle was delivered encrypted
    """

    bundle_id: str
    version: str
    tier: str
    signatures: SignatureSet
    expires_at: datetime | None = None
    is_encrypted: bool = False

    @property
    def is_expired(self) -> bool:
        """Check if this bundle's license has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def is_free(self) -> bool:
        """Check if this is a free-tier bundle."""
        return self.tier == "free"

    @property
    def time_until_expiry(self) -> float | None:
        """Get seconds until expiration, or None if no expiration."""
        if self.expires_at is None:
            return None
        delta = self.expires_at - datetime.now(timezone.utc)
        return delta.total_seconds()

    def __repr__(self) -> str:
        status = "expired" if self.is_expired else "active"
        return (
            f"SignatureBundle(id={self.bundle_id!r}, version={self.version!r}, "
            f"tier={self.tier!r}, signatures={len(self.signatures.signatures)}, "
            f"status={status})"
        )


@dataclass
class SignatureBundleSet:
    """Collection of signature bundles with expiration tracking.

    This class manages multiple bundles and provides methods to:
    - Get only active (non-expired) signatures
    - Track earliest expiration for re-sync scheduling
    - Warn about expiring bundles
    """

    bundles: list[SignatureBundle] = field(default_factory=list)

    def get_active_signatures(self) -> SignatureSet:
        """Return merged SignatureSet from all non-expired bundles.

        Expired paid bundles are skipped with a warning.
        Free bundles never expire.

        Returns:
            SignatureSet containing all active signatures
        """
        from aiproxyguard.signatures.models import SignatureSet

        active_sigs = []
        for bundle in self.bundles:
            sig_count = len(bundle.signatures.signatures)
            pattern_count = len(bundle.signatures.all_patterns())

            if bundle.is_expired:
                if not bundle.is_free:
                    logger.warning(
                        f"Bundle {bundle.bundle_id} EXPIRED at {bundle.expires_at}, "
                        f"skipping {sig_count} signatures"
                    )
                continue

            # Log license status for each active bundle
            if bundle.expires_at:
                time_left = bundle.time_until_expiry
                hours_left = time_left / 3600 if time_left else 0
                logger.info(
                    f"Bundle {bundle.bundle_id} ACTIVE: {sig_count} signatures, "
                    f"{pattern_count} patterns, expires in {hours_left:.1f}h"
                )
            else:
                logger.info(
                    f"Bundle {bundle.bundle_id} ACTIVE (free tier): {sig_count} signatures, "
                    f"{pattern_count} patterns, no expiration"
                )

            active_sigs.extend(bundle.signatures.signatures)

        return SignatureSet(signatures=active_sigs)

    def get_earliest_expiration(self) -> datetime | None:
        """Get the earliest expiration time across all bundles.

        Useful for scheduling re-sync before bundles expire.

        Returns:
            Earliest expiration datetime, or None if all bundles are free tier
        """
        expirations = [
            b.expires_at
            for b in self.bundles
            if b.expires_at is not None and not b.is_expired
        ]
        return min(expirations) if expirations else None

    def get_expiring_soon(self, within_hours: float = 24) -> list[SignatureBundle]:
        """Get bundles expiring within the specified time.

        Args:
            within_hours: Number of hours to look ahead

        Returns:
            List of bundles expiring soon
        """
        threshold_seconds = within_hours * 3600
        expiring = []
        for bundle in self.bundles:
            time_left = bundle.time_until_expiry
            if time_left is not None and 0 < time_left < threshold_seconds:
                expiring.append(bundle)
        return expiring

    @property
    def total_signatures(self) -> int:
        """Total number of signatures across all bundles (including expired)."""
        return sum(len(b.signatures.signatures) for b in self.bundles)

    @property
    def active_signatures_count(self) -> int:
        """Number of active (non-expired) signatures."""
        return sum(
            len(b.signatures.signatures)
            for b in self.bundles
            if not b.is_expired
        )

    def get_bundle(self, bundle_id: str) -> SignatureBundle | None:
        """Get a specific bundle by ID."""
        for bundle in self.bundles:
            if bundle.bundle_id == bundle_id:
                return bundle
        return None

    def __repr__(self) -> str:
        active = sum(1 for b in self.bundles if not b.is_expired)
        expired = len(self.bundles) - active
        return (
            f"SignatureBundleSet(bundles={len(self.bundles)}, "
            f"active={active}, expired={expired}, "
            f"signatures={self.active_signatures_count})"
        )
