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

"""Cryptographic utilities for license validation and content decryption."""

from aiproxyguard.crypto.license import (
    License,
    EncryptedContentHeader,
    parse_license,
    verify_license_signature,
    is_license_valid,
    decrypt_content,
    parse_encrypted_header,
)

__all__ = [
    "License",
    "EncryptedContentHeader",
    "parse_license",
    "verify_license_signature",
    "is_license_valid",
    "decrypt_content",
    "parse_encrypted_header",
]
