#!/usr/bin/env python3
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

"""
Upload signature bundles to AIProxyGuard Control Plane

Usage:
    python scripts/upload_signatures.py [--url https://control-plane-url] [--token TOKEN]
"""

import argparse
import os
import sys
from pathlib import Path

import httpx

# Signature metadata
BUNDLES = [
    {
        "file": "prompt_injection.yaml",
        "name": "prompt_injection",
        "version": "2026.03.24.001",
        "tier": "free",
        "category": "prompt_injection",
        "description": "Detects prompt injection attacks including instruction override, delimiter injection, and system prompt extraction",
    },
    {
        "file": "jailbreak.yaml",
        "name": "jailbreak",
        "version": "2026.03.24.001",
        "tier": "free",
        "category": "jailbreak",
        "description": "Detects jailbreak attempts including DAN mode, persona exploits, restriction bypass",
    },
    {
        "file": "pii.yaml",
        "name": "pii",
        "version": "2026.03.24.001",
        "tier": "free",
        "category": "pii",
        "description": "Detects PII extraction attempts including SSN, credit cards, emails, credentials",
    },
    {
        "file": "phi.yaml",
        "name": "phi",
        "version": "2026.03.24.001",
        "tier": "pro",
        "category": "phi",
        "description": "HIPAA-compliant PHI detection including medical records, diagnoses, treatments",
    },
    {
        "file": "child_protection.yaml",
        "name": "child_protection",
        "version": "2026.03.24.001",
        "tier": "free",
        "category": "child_protection",
        "description": "Child safety signatures detecting grooming, CSAM requests, exploitation",
    },
    {
        "file": "encoding_evasion.yaml",
        "name": "encoding_evasion",
        "version": "2026.03.24.001",
        "tier": "free",
        "category": "encoding_evasion",
        "description": "Detects filter bypass attempts using Base64, hex, unicode, leetspeak",
    },
    {
        "file": "data_exfil.yaml",
        "name": "data_exfil",
        "version": "2026.03.24.001",
        "tier": "pro",
        "category": "data_exfil",
        "description": "Detects data exfiltration attempts including database dumps, API key extraction",
    },
    {
        "file": "harmful_content.yaml",
        "name": "harmful_content",
        "version": "2026.03.24.001",
        "tier": "pro",
        "category": "harmful_content",
        "description": "Detects requests for violence, weapons, drugs, hacking, fraud",
    },
]


def login(base_url: str, email: str, password: str) -> str:
    """Login and get access token."""
    response = httpx.post(
        f"{base_url}/api/auth/login",
        json={"email": email, "password": password},
    )
    response.raise_for_status()
    return response.cookies.get("access_token") or response.json().get("access_token")


def upload_bundle(base_url: str, cookies: dict, bundle: dict, signatures_dir: Path) -> bool:
    """Upload a single signature bundle."""
    file_path = signatures_dir / bundle["file"]
    if not file_path.exists():
        print(f"  File not found: {file_path}")
        return False

    with open(file_path, "rb") as f:
        files = {"file": (bundle["file"], f, "text/yaml")}
        data = {
            "name": bundle["name"],
            "version": bundle["version"],
            "tier": bundle["tier"],
            "file_type": "yaml",
            "category": bundle["category"],
            "description": bundle["description"],
        }

        response = httpx.post(
            f"{base_url}/api/admin/signatures",
            files=files,
            data=data,
            cookies=cookies,
            timeout=30.0,
        )

        if response.status_code in (200, 201):
            result = response.json()
            print(f"  Uploaded: {bundle['name']} v{bundle['version']} ({result.get('signature_count', '?')} signatures)")
            return True
        else:
            print(f"  Failed: {response.status_code} - {response.text[:200]}")
            return False


def main():
    parser = argparse.ArgumentParser(description="Upload signatures to AIProxyGuard control plane")
    parser.add_argument(
        "--url",
        default=os.environ.get("CONTROL_PLANE_URL", "https://aiproxyguard-qb247.ondigitalocean.app"),
        help="Control plane URL",
    )
    parser.add_argument(
        "--email",
        default=os.environ.get("ADMIN_EMAIL", "admin@aiproxyguard.com"),
        help="Admin email",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("ADMIN_PASSWORD"),
        help="Admin password",
    )
    parser.add_argument(
        "--signatures-dir",
        default=Path(__file__).parent.parent / "signatures",
        type=Path,
        help="Signatures directory",
    )
    args = parser.parse_args()

    if not args.password:
        args.password = input("Admin password: ")

    print(f"\nUploading signatures to {args.url}")
    print(f"Signatures directory: {args.signatures_dir}\n")

    # Login
    print("Logging in...")
    try:
        response = httpx.post(
            f"{args.url}/api/auth/login",
            json={"email": args.email, "password": args.password},
            follow_redirects=True,
        )
        response.raise_for_status()
        cookies = dict(response.cookies)
        print(f"  Logged in as {args.email}\n")
    except httpx.HTTPError as e:
        print(f"  Login failed: {e}")
        return 1

    # Upload bundles
    print("Uploading signature bundles:")
    success = 0
    failed = 0

    for bundle in BUNDLES:
        if upload_bundle(args.url, cookies, bundle, args.signatures_dir):
            success += 1
        else:
            failed += 1

    print(f"\nDone: {success} uploaded, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
