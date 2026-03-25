from __future__ import annotations
from pathlib import Path
from typing import Any
import yaml
from aiproxyguard.signatures.models import Signature, SignatureSet


def _parse_signature(data: dict[str, Any]) -> Signature:
    return Signature(
        id=data["id"], name=data["name"], category=data["category"],
        severity=data["severity"], patterns=data["patterns"], action=data["action"],
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

    Args:
        bundles: List of bundle dicts from control plane API.

    Returns:
        SignatureSet containing all parsed signatures from all bundles.
    """
    signatures: list[Signature] = []
    for bundle in bundles:
        content = bundle.get("content", "")
        if content:
            data = yaml.safe_load(content)
            if data and "signatures" in data:
                for sig_data in data["signatures"]:
                    signatures.append(_parse_signature(sig_data))
    return SignatureSet(signatures=signatures)
