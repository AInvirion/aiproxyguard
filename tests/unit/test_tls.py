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

"""Tests for TLS interception module."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aiproxyguard.tls import (
    CertificateAuthority,
    CertificateCache,
    TLSConfig,
    generate_ca,
    load_tls_config,
)


class TestCertificateCache:
    """Tests for certificate cache."""

    def test_put_and_get(self):
        """Test basic put and get operations."""
        cache = CertificateCache(max_size=10)

        cache.put("example.com", b"cert_pem", b"key_pem")
        result = cache.get("example.com")

        assert result == (b"cert_pem", b"key_pem")

    def test_get_missing(self):
        """Test getting a missing entry."""
        cache = CertificateCache(max_size=10)

        result = cache.get("missing.com")

        assert result is None

    def test_eviction(self):
        """Test LRU eviction when cache is full."""
        cache = CertificateCache(max_size=3)

        cache.put("host1.com", b"cert1", b"key1")
        cache.put("host2.com", b"cert2", b"key2")
        cache.put("host3.com", b"cert3", b"key3")

        # Access host1 to make it recently used
        cache.get("host1.com")

        # Add new entry, should evict host2 (LRU)
        cache.put("host4.com", b"cert4", b"key4")

        assert cache.get("host1.com") is not None
        assert cache.get("host2.com") is None  # Evicted
        assert cache.get("host3.com") is not None
        assert cache.get("host4.com") is not None

    def test_clear(self):
        """Test clearing the cache."""
        cache = CertificateCache(max_size=10)
        cache.put("example.com", b"cert", b"key")

        cache.clear()

        assert cache.get("example.com") is None


class TestGenerateCA:
    """Tests for CA generation."""

    def test_generate_ca_creates_files(self):
        """Test that generate_ca creates cert and key files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "ca.crt")
            key_path = os.path.join(tmpdir, "ca.key")

            cert_pem, key_pem = generate_ca(
                output_cert=cert_path,
                output_key=key_path,
                common_name="Test CA",
                organization="Test Org",
                validity_days=365,
                key_size=2048,
            )

            # Check files exist
            assert os.path.exists(cert_path)
            assert os.path.exists(key_path)

            # Check file permissions on key
            key_mode = os.stat(key_path).st_mode & 0o777
            assert key_mode == 0o600

            # Verify certificate
            cert = x509.load_pem_x509_certificate(cert_pem)
            assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Test CA"
            assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Test Org"

            # Verify it's a CA certificate
            basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            assert basic_constraints.value.ca is True

            # Verify key
            key = serialization.load_pem_private_key(key_pem, password=None)
            assert isinstance(key, rsa.RSAPrivateKey)

    def test_generate_ca_creates_parent_directories(self):
        """Test that generate_ca creates parent directories if needed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "subdir", "nested", "ca.crt")
            key_path = os.path.join(tmpdir, "subdir", "nested", "ca.key")

            generate_ca(
                output_cert=cert_path,
                output_key=key_path,
                key_size=2048,
            )

            assert os.path.exists(cert_path)
            assert os.path.exists(key_path)


class TestCertificateAuthority:
    """Tests for CertificateAuthority class."""

    @pytest.fixture
    def ca_files(self):
        """Create CA certificate and key files for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_path = os.path.join(tmpdir, "ca.crt")
            key_path = os.path.join(tmpdir, "ca.key")

            generate_ca(
                output_cert=cert_path,
                output_key=key_path,
                key_size=2048,
            )

            yield cert_path, key_path

    def test_load_ca(self, ca_files):
        """Test loading CA certificate and key."""
        cert_path, key_path = ca_files

        ca = CertificateAuthority(cert_path, key_path)
        ca.load()

        assert ca.ca_cert is not None
        assert ca.ca_key is not None

    def test_load_missing_cert(self):
        """Test loading with missing certificate file."""
        ca = CertificateAuthority("/nonexistent/ca.crt", "/nonexistent/ca.key")

        with pytest.raises(FileNotFoundError):
            ca.load()

    def test_generate_certificate(self, ca_files):
        """Test generating a certificate for a hostname."""
        cert_path, key_path = ca_files

        ca = CertificateAuthority(cert_path, key_path)
        ca.load()

        cert_pem, key_pem = ca.generate_certificate("api.openai.com")

        # Verify certificate
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "api.openai.com"

        # Verify SAN
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        assert "api.openai.com" in dns_names

        # Verify it's NOT a CA
        basic_constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert basic_constraints.value.ca is False

        # Verify signed by CA
        assert cert.issuer == ca.ca_cert.subject

        # Verify key
        key = serialization.load_pem_private_key(key_pem, password=None)
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_generate_certificate_caching(self, ca_files):
        """Test that certificates are cached."""
        cert_path, key_path = ca_files

        ca = CertificateAuthority(cert_path, key_path, cache_size=10)
        ca.load()

        # Generate twice
        cert1, key1 = ca.generate_certificate("test.com")
        cert2, key2 = ca.generate_certificate("test.com")

        # Should return cached version
        assert cert1 == cert2
        assert key1 == key2

    def test_get_ca_cert_pem(self, ca_files):
        """Test getting CA certificate in PEM format."""
        cert_path, key_path = ca_files

        ca = CertificateAuthority(cert_path, key_path)
        ca.load()

        pem = ca.get_ca_cert_pem()

        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert pem.strip().endswith(b"-----END CERTIFICATE-----")

    def test_not_loaded_raises_error(self):
        """Test that accessing CA before load raises error."""
        ca = CertificateAuthority("/dummy/ca.crt", "/dummy/ca.key")

        with pytest.raises(RuntimeError, match="CA not loaded"):
            _ = ca.ca_cert

        with pytest.raises(RuntimeError, match="CA not loaded"):
            _ = ca.ca_key


class TestTLSConfig:
    """Tests for TLS configuration."""

    def test_load_tls_config_defaults(self):
        """Test loading TLS config with defaults."""
        config = load_tls_config({})

        assert config.enabled is False
        assert config.ca_cert == "/etc/aiproxyguard/ca.crt"
        assert config.ca_key == "/etc/aiproxyguard/ca.key"
        assert config.cert_cache_size == 1000
        assert config.cert_validity_days == 30

    def test_load_tls_config_custom(self):
        """Test loading TLS config with custom values."""
        config = load_tls_config({
            "enabled": True,
            "ca_cert": "/custom/ca.crt",
            "ca_key": "/custom/ca.key",
            "cert_cache_size": 500,
            "cert_validity_days": 7,
        })

        assert config.enabled is True
        assert config.ca_cert == "/custom/ca.crt"
        assert config.ca_key == "/custom/ca.key"
        assert config.cert_cache_size == 500
        assert config.cert_validity_days == 7
