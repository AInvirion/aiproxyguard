"""TLS interception with on-the-fly certificate generation.

This module provides MITM-style TLS interception for inspecting HTTPS traffic
to upstream LLM providers. Clients must trust the CA certificate.
"""

from __future__ import annotations

import hashlib
import os
import ssl
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    from cryptography.x509 import Certificate

from aiproxyguard.logging import get_logger

logger = get_logger("tls")


@dataclass
class TLSConfig:
    """TLS configuration."""

    enabled: bool = False
    ca_cert: str = "/etc/aiproxyguard/ca.crt"
    ca_key: str = "/etc/aiproxyguard/ca.key"
    cert_cache_size: int = 1000
    cert_validity_days: int = 30


class CertificateCache:
    """Thread-safe LRU cache for generated certificates."""

    def __init__(self, max_size: int = 1000) -> None:
        self._cache: dict[str, tuple[bytes, bytes]] = {}
        self._order: list[str] = []
        self._max_size = max_size
        self._lock = threading.Lock()

    def get(self, hostname: str) -> tuple[bytes, bytes] | None:
        """Get cached certificate and key for hostname."""
        with self._lock:
            if hostname in self._cache:
                # Move to end (most recently used)
                self._order.remove(hostname)
                self._order.append(hostname)
                return self._cache[hostname]
        return None

    def put(self, hostname: str, cert_pem: bytes, key_pem: bytes) -> None:
        """Cache certificate and key for hostname."""
        with self._lock:
            if hostname in self._cache:
                self._order.remove(hostname)
            elif len(self._cache) >= self._max_size:
                # Evict least recently used
                oldest = self._order.pop(0)
                del self._cache[oldest]

            self._cache[hostname] = (cert_pem, key_pem)
            self._order.append(hostname)

    def clear(self) -> None:
        """Clear the cache."""
        with self._lock:
            self._cache.clear()
            self._order.clear()


class CertificateAuthority:
    """Certificate Authority for generating certificates on-the-fly."""

    def __init__(
        self,
        ca_cert_path: str,
        ca_key_path: str,
        cache_size: int = 1000,
        cert_validity_days: int = 30,
    ) -> None:
        self._ca_cert_path = Path(ca_cert_path)
        self._ca_key_path = Path(ca_key_path)
        self._cert_validity_days = cert_validity_days
        self._cache = CertificateCache(max_size=cache_size)

        # Load CA certificate and key
        self._ca_cert: Certificate | None = None
        self._ca_key: RSAPrivateKey | None = None
        self._loaded = False

    def load(self) -> None:
        """Load CA certificate and key from files."""
        if not self._ca_cert_path.exists():
            raise FileNotFoundError(f"CA certificate not found: {self._ca_cert_path}")
        if not self._ca_key_path.exists():
            raise FileNotFoundError(f"CA key not found: {self._ca_key_path}")

        # Load CA certificate
        with open(self._ca_cert_path, "rb") as f:
            self._ca_cert = x509.load_pem_x509_certificate(f.read())

        # Load CA private key
        with open(self._ca_key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
            if not isinstance(key, rsa.RSAPrivateKey):
                raise ValueError("CA key must be RSA")
            self._ca_key = key

        self._loaded = True
        logger.info(
            "CA loaded",
            extra={
                "ca_cert": str(self._ca_cert_path),
                "ca_subject": self._ca_cert.subject.rfc4514_string(),
            },
        )

    @property
    def ca_cert(self) -> "Certificate":
        """Get the CA certificate."""
        if not self._loaded or self._ca_cert is None:
            raise RuntimeError("CA not loaded. Call load() first.")
        return self._ca_cert

    @property
    def ca_key(self) -> "RSAPrivateKey":
        """Get the CA private key."""
        if not self._loaded or self._ca_key is None:
            raise RuntimeError("CA not loaded. Call load() first.")
        return self._ca_key

    def generate_certificate(self, hostname: str) -> tuple[bytes, bytes]:
        """Generate a certificate for the given hostname.

        Returns:
            Tuple of (certificate_pem, private_key_pem)
        """
        # Check cache first
        cached = self._cache.get(hostname)
        if cached:
            logger.debug(f"Using cached certificate for {hostname}")
            return cached

        logger.debug(f"Generating certificate for {hostname}")

        # Generate a new key pair for this certificate
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create certificate
        now = datetime.now(timezone.utc)
        # Start validity slightly in the past to handle clock skew
        not_before = now - timedelta(hours=1)
        not_after = now + timedelta(days=self._cert_validity_days)

        # Generate a deterministic serial number based on hostname and time
        serial_data = f"{hostname}:{now.isoformat()}".encode()
        serial_number = int(hashlib.sha256(serial_data).hexdigest()[:16], 16)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AIProxyGuard"),
        ])

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(serial_number)
            .not_valid_before(not_before)
            .not_valid_after(not_after)
        )

        # Add Subject Alternative Name extension
        san = x509.SubjectAlternativeName([
            x509.DNSName(hostname),
        ])
        builder = builder.add_extension(san, critical=False)

        # Add Basic Constraints (not a CA)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        # Add Key Usage
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Add Extended Key Usage (server auth)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )

        # Add Subject Key Identifier
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )

        # Add Authority Key Identifier from CA cert
        try:
            ca_ski = self.ca_cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER
            )
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier(
                    key_identifier=ca_ski.value.digest,  # type: ignore[attr-defined]
                    authority_cert_issuer=None,
                    authority_cert_serial_number=None,
                ),
                critical=False,
            )
        except x509.ExtensionNotFound:
            # CA doesn't have SKI, compute from public key
            builder = builder.add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_cert.public_key()  # type: ignore[arg-type]
                ),
                critical=False,
            )

        # Sign with CA key
        cert = builder.sign(self.ca_key, hashes.SHA256())

        # Serialize to PEM
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )

        # Cache the result
        self._cache.put(hostname, cert_pem, key_pem)

        return cert_pem, key_pem

    def get_ca_cert_pem(self) -> bytes:
        """Get the CA certificate in PEM format."""
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)


class TLSContextFactory:
    """Factory for creating SSL contexts for TLS interception."""

    def __init__(self, ca: CertificateAuthority) -> None:
        self._ca = ca
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._lock = threading.Lock()

    def get_server_context(self, hostname: str) -> ssl.SSLContext:
        """Get an SSL context for serving TLS to clients."""
        with self._lock:
            if hostname in self._contexts:
                return self._contexts[hostname]

        # Generate certificate for this hostname
        cert_pem, key_pem = self._ca.generate_certificate(hostname)

        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load certificate and key from memory
        # We need to write to temp files since load_cert_chain doesn't accept bytes
        import tempfile

        with tempfile.NamedTemporaryFile(delete=False, suffix=".crt") as cert_file:
            cert_file.write(cert_pem)
            cert_path = cert_file.name

        with tempfile.NamedTemporaryFile(delete=False, suffix=".key") as key_file:
            key_file.write(key_pem)
            key_path = key_file.name

        try:
            context.load_cert_chain(cert_path, key_path)
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

        with self._lock:
            self._contexts[hostname] = context

        return context

    def get_client_context(self) -> ssl.SSLContext:
        """Get an SSL context for connecting to upstream servers."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_default_certs()
        return context


def generate_ca(
    output_cert: str,
    output_key: str,
    common_name: str = "AIProxyGuard CA",
    organization: str = "AIProxyGuard",
    validity_days: int = 3650,  # 10 years
    key_size: int = 4096,
) -> tuple[bytes, bytes]:
    """Generate a new CA certificate and private key.

    Args:
        output_cert: Path to write the CA certificate
        output_key: Path to write the CA private key
        common_name: Common name for the CA certificate
        organization: Organization name for the CA certificate
        validity_days: Number of days the CA certificate is valid
        key_size: RSA key size in bits

    Returns:
        Tuple of (certificate_pem, private_key_pem)
    """
    logger.info(f"Generating CA certificate: {common_name}")

    # Generate RSA key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )

    # Create subject/issuer (same for self-signed CA)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    ])

    # Set validity period
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(hours=1)  # Handle clock skew
    not_after = now + timedelta(days=validity_days)

    # Generate serial number
    serial_number = x509.random_serial_number()

    # Build certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    # Add Basic Constraints (this IS a CA)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    )

    # Add Key Usage
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )

    # Add Subject Key Identifier
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
        critical=False,
    )

    # Self-sign
    cert = builder.sign(key, hashes.SHA256())

    # Serialize to PEM
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    # Write to files
    output_cert_path = Path(output_cert)
    output_key_path = Path(output_key)

    # Create directories if needed
    output_cert_path.parent.mkdir(parents=True, exist_ok=True)
    output_key_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_cert_path, "wb") as f:
        f.write(cert_pem)

    with open(output_key_path, "wb") as f:
        f.write(key_pem)

    # Set restrictive permissions on key file
    os.chmod(output_key_path, 0o600)

    logger.info(
        "CA certificate generated",
        extra={
            "cert_path": str(output_cert_path),
            "key_path": str(output_key_path),
            "validity_days": validity_days,
        },
    )

    return cert_pem, key_pem


def load_tls_config(data: dict[str, Any]) -> TLSConfig:
    """Load TLS configuration from dict."""
    return TLSConfig(
        enabled=data.get("enabled", False),
        ca_cert=data.get("ca_cert", "/etc/aiproxyguard/ca.crt"),
        ca_key=data.get("ca_key", "/etc/aiproxyguard/ca.key"),
        cert_cache_size=data.get("cert_cache_size", 1000),
        cert_validity_days=data.get("cert_validity_days", 30),
    )
