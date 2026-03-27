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

from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from aiproxyguard.signatures.models import Signature, SignatureSet

if TYPE_CHECKING:
    from aiproxyguard.crypto.license import License
    from aiproxyguard.signatures.bundle import SignatureBundle, SignatureBundleSet

logger = logging.getLogger(__name__)


def _parse_signature(data: dict[str, Any]) -> Signature:
    # Support both 'pattern' (single string) and 'patterns' (list) formats
    patterns = data.get("patterns", [])
    if not patterns and "pattern" in data:
        patterns = [data["pattern"]]
    # Category defaults to 'unknown' if not provided (backwards compatibility)
    category = data.get("category", "unknown")
    return Signature(
        id=data["id"], name=data["name"], category=category,
        severity=data["severity"], patterns=patterns, action=data["action"],
        scan_target=data.get("scan_target", "request"),
    )


def load_signatures(path: str) -> SignatureSet:
    sig_path = Path(path)
    signatures: list[Signature] = []
    if not sig_path.exists():
        return SignatureSet(signatures=[])
    if sig_path.is_file():
        yaml_files = [sig_path]
    else:
        yaml_files = list(sig_path.glob("*.yaml")) + list(sig_path.glob("*.yml"))
    for yaml_file in yaml_files:
        with open(yaml_file) as f:
            data = yaml.safe_load(f)
        if data and "signatures" in data:
            for sig_data in data["signatures"]:
                signatures.append(_parse_signature(sig_data))
    return SignatureSet(signatures=signatures)


def parse_signatures_from_yaml(yaml_content: str) -> SignatureSet:
    """Parse signatures from YAML string content.

    This is used for hot-reloading signatures fetched from the control plane.

    Args:
        yaml_content: YAML string containing signatures in the standard format.

    Returns:
        SignatureSet containing parsed signatures.
    """
    signatures: list[Signature] = []
    data = yaml.safe_load(yaml_content)
    if data and "signatures" in data:
        for sig_data in data["signatures"]:
            signatures.append(_parse_signature(sig_data))
    return SignatureSet(signatures=signatures)


def parse_signatures_from_bundles(bundles: list[dict[str, Any]]) -> SignatureSet:
    """Parse signatures from control plane bundle format.

    Each bundle contains a 'content' field with YAML signature definitions.
    The content may contain multiple concatenated files (marked with # === filename ===)
    which have duplicate 'signatures:' keys that YAML would otherwise overwrite.

    Args:
        bundles: List of bundle dicts from control plane API.

    Returns:
        SignatureSet containing all parsed signatures from all bundles.
    """
    signatures: list[Signature] = []
    for bundle in bundles:
        content = bundle.get("content", "")
        if not content:
            continue

        # Check if content has section markers (concatenated files)
        # Pattern: # === path/to/file.yaml ===
        if re.search(r"^# === .+\.yaml ===", content, re.MULTILINE):
            # Split by section markers and parse each section
            sections = re.split(r"^# === .+\.yaml ===\n?", content, flags=re.MULTILINE)
            for section in sections:
                section = section.strip()
                if not section:
                    continue
                try:
                    data = yaml.safe_load(section)
                    if data and "signatures" in data:
                        for sig_data in data["signatures"]:
                            signatures.append(_parse_signature(sig_data))
                except yaml.YAMLError:
                    continue
        else:
            # Single document - try safe_load_all for --- separated docs
            try:
                for data in yaml.safe_load_all(content):
                    if data and "signatures" in data:
                        for sig_data in data["signatures"]:
                            signatures.append(_parse_signature(sig_data))
            except yaml.YAMLError:
                # Fall back to single document
                data = yaml.safe_load(content)
                if data and "signatures" in data:
                    for sig_data in data["signatures"]:
                        signatures.append(_parse_signature(sig_data))

    return SignatureSet(signatures=signatures)


def _parse_yaml_content(content: str) -> list[Signature]:
    """Parse YAML content that may be concatenated or multi-document.

    Args:
        content: YAML string content

    Returns:
        List of parsed Signature objects
    """
    signatures: list[Signature] = []

    # Check if content has section markers (concatenated files)
    if re.search(r"^# === .+\.yaml ===", content, re.MULTILINE):
        sections = re.split(r"^# === .+\.yaml ===\n?", content, flags=re.MULTILINE)
        for section in sections:
            section = section.strip()
            if not section:
                continue
            try:
                data = yaml.safe_load(section)
                if data and "signatures" in data:
                    for sig_data in data["signatures"]:
                        signatures.append(_parse_signature(sig_data))
            except yaml.YAMLError:
                continue
    else:
        # Try multi-document YAML
        try:
            for data in yaml.safe_load_all(content):
                if data and "signatures" in data:
                    for sig_data in data["signatures"]:
                        signatures.append(_parse_signature(sig_data))
        except yaml.YAMLError:
            # Fall back to single document
            data = yaml.safe_load(content)
            if data and "signatures" in data:
                for sig_data in data["signatures"]:
                    signatures.append(_parse_signature(sig_data))

    return signatures


def parse_bundles_to_bundle_set(
    bundle_contents: list[dict[str, Any]],
    licenses: dict[str, License] | None = None,
) -> SignatureBundleSet:
    """Parse bundle data into SignatureBundleSet with expiration tracking.

    This is the new preferred method for parsing bundles as it preserves
    bundle-level metadata including expiration times from licenses.

    Args:
        bundle_contents: List of bundle dicts with 'bundle_id', 'version',
                        'tier', and 'content' fields.
        licenses: Optional dict mapping bundle_id to License objects.
                 Used to set expiration times for encrypted bundles.

    Returns:
        SignatureBundleSet containing all parsed bundles with metadata.
    """
    from aiproxyguard.signatures.bundle import SignatureBundle, SignatureBundleSet

    bundles: list[SignatureBundle] = []

    for bundle_data in bundle_contents:
        bundle_id = bundle_data.get("bundle_id", "")
        version = bundle_data.get("version", "")
        tier = bundle_data.get("tier", "free")
        content = bundle_data.get("content", "")
        is_encrypted = bundle_data.get("is_encrypted", False)

        if not bundle_id:
            logger.warning("Bundle missing bundle_id, skipping")
            continue

        # Parse signatures from content
        signatures = _parse_yaml_content(content) if content else []
        sig_set = SignatureSet(signatures=signatures)

        # Get expiration from license if available
        expires_at: datetime | None = None
        if licenses and bundle_id in licenses:
            license = licenses[bundle_id]
            expires_at = license.expires_at

        bundle = SignatureBundle(
            bundle_id=bundle_id,
            version=version,
            tier=tier,
            signatures=sig_set,
            expires_at=expires_at,
            is_encrypted=is_encrypted,
        )
        bundles.append(bundle)

        logger.debug(
            f"Parsed bundle {bundle_id}: {len(signatures)} signatures, "
            f"tier={tier}, expires={expires_at}"
        )

    return SignatureBundleSet(bundles=bundles)
