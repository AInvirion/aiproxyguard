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

"""Configuration loading with environment variable substitution."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ServerConfig:
    """Server configuration."""

    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 4


@dataclass
class UpstreamConfig:
    """Upstream LLM provider configuration."""

    url: str
    timeout: int = 60
    auth_header: str | None = "Authorization"


@dataclass
class ResponseScannerConfig:
    """Response scanner configuration."""

    enabled: bool = False
    mode: str = "buffered"  # passthrough, buffered, full
    buffer_size: int = 1024  # chars to buffer before first scan in buffered mode
    categories: list[str] = field(default_factory=list)  # empty = all categories


@dataclass
class ScannerConfig:
    """Scanner configuration."""

    enabled: bool = True
    regex: bool = True
    heuristics: bool = True
    ml_classifier: bool = False
    response: ResponseScannerConfig = field(default_factory=ResponseScannerConfig)


@dataclass
class PolicyCategoryConfig:
    """Per-category policy configuration."""

    action: str = "block"
    threshold: float = 0.8


@dataclass
class PolicyConfig:
    """Policy configuration."""

    default_action: str = "block"
    categories: dict[str, PolicyCategoryConfig] = field(default_factory=dict)
    allowlists: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SignatureConfig:
    """Signature configuration."""

    path: str = "/etc/aiproxyguard/signatures"


@dataclass
class SecurityConfig:
    """Security and resilience configuration."""

    failure_mode: str = "open"
    scanner_timeout_ms: int = 100
    upstream_timeout_s: int = 60


@dataclass
class MetricsConfig:
    """Metrics configuration."""

    enabled: bool = True
    path: str = "/metrics"


@dataclass
class LoggingConfig:
    """Logging configuration."""

    level: str = "info"
    format: str = "json"
    redact_keys: bool = True


@dataclass
class ControlPlaneConfig:
    """Control plane configuration."""

    enabled: bool = False
    url: str = ""
    api_key: str = ""
    heartbeat_interval: int = 60
    sync_signatures: bool = True
    report_telemetry: bool = True
    manifest_public_key: str = ""  # Ed25519 public key (base64) for manifest verification


@dataclass
class TLSConfig:
    """TLS interception configuration."""

    enabled: bool = False
    ca_cert: str = "/etc/aiproxyguard/ca.crt"
    ca_key: str = "/etc/aiproxyguard/ca.key"
    cert_cache_size: int = 1000
    cert_validity_days: int = 30


@dataclass
class IdentityConfig:
    """Client identity resolution configuration."""

    method: str = "ip"  # ip, header, token, mtls
    header_name: str = "X-Client-ID"
    fallback_header: str | None = None
    trust_xff: bool = False  # Trust X-Forwarded-For for IP resolution
    hash_token: bool = True  # Hash tokens for privacy


@dataclass
class Config:
    """Root configuration."""

    server: ServerConfig
    upstreams: dict[str, UpstreamConfig]
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    signatures: SignatureConfig = field(default_factory=SignatureConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    control_plane: ControlPlaneConfig = field(default_factory=ControlPlaneConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    identity: IdentityConfig = field(default_factory=IdentityConfig)


ENV_VAR_PATTERN = re.compile(r"\$\{([^}:]+)(?::-([^}]*))?\}")


def _substitute_env_vars(value: str) -> str:
    """Substitute ${VAR} and ${VAR:-default} patterns."""

    def replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        default = match.group(2)
        return os.environ.get(var_name, default if default is not None else "")

    return ENV_VAR_PATTERN.sub(replace, value)


def _process_value(value: Any) -> Any:
    """Recursively process values for env var substitution."""
    if isinstance(value, str):
        return _substitute_env_vars(value)
    if isinstance(value, dict):
        return {k: _process_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_process_value(v) for v in value]
    return value


def _parse_upstream(name: str, data: dict[str, Any]) -> UpstreamConfig:
    """Parse upstream configuration."""
    if "url" not in data:
        raise ValueError(f"Upstream '{name}' missing required field: url")

    timeout_str = data.get("timeout", "60s")
    if isinstance(timeout_str, str) and timeout_str.endswith("s"):
        timeout = int(timeout_str[:-1])
    else:
        timeout = int(timeout_str)

    return UpstreamConfig(
        url=data["url"],
        timeout=timeout,
        auth_header=data.get("auth_header", "Authorization"),
    )


def load_config(path: str) -> Config:
    """Load configuration from YAML file."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(config_path) as f:
        raw = yaml.safe_load(f)

    data = _process_value(raw)

    server_data = data.get("server", {})
    if "port" not in server_data:
        raise ValueError("Missing required field: server.port")

    server = ServerConfig(
        host=server_data.get("host", "0.0.0.0"),
        port=server_data["port"],
        workers=server_data.get("workers", 4),
    )

    upstreams_data = data.get("upstreams", {})
    upstreams = {
        name: _parse_upstream(name, upstream_data)
        for name, upstream_data in upstreams_data.items()
    }

    scanner_data = data.get("scanner", {})
    response_data = scanner_data.get("response", {})
    response_config = ResponseScannerConfig(
        enabled=response_data.get("enabled", False),
        mode=response_data.get("mode", "buffered"),
        buffer_size=response_data.get("buffer_size", 1024),
        categories=response_data.get("categories", []),
    )
    scanner = ScannerConfig(
        enabled=scanner_data.get("enabled", True),
        regex=scanner_data.get("regex", True),
        heuristics=scanner_data.get("heuristics", True),
        ml_classifier=scanner_data.get("ml_classifier", False),
        response=response_config,
    )

    security_data = data.get("security", {})
    security = SecurityConfig(
        failure_mode=security_data.get("failure_mode", "open"),
        scanner_timeout_ms=security_data.get("scanner_timeout_ms", 100),
        upstream_timeout_s=security_data.get("upstream_timeout_s", 60),
    )

    metrics_data = data.get("metrics", {})
    metrics = MetricsConfig(
        enabled=metrics_data.get("enabled", True),
        path=metrics_data.get("path", "/metrics"),
    )

    policy_data = data.get("policy", {})
    categories_data = policy_data.get("categories", {})
    categories = {
        name: PolicyCategoryConfig(
            action=cat.get("action", "block"),
            threshold=cat.get("threshold", 0.8),
        )
        for name, cat in categories_data.items()
    }
    policy = PolicyConfig(
        default_action=policy_data.get("default_action", "block"),
        categories=categories,
        allowlists=policy_data.get("allowlists", []),
    )

    logging_data = data.get("logging", {})
    logging = LoggingConfig(
        level=logging_data.get("level", "info"),
        format=logging_data.get("format", "json"),
        redact_keys=logging_data.get("redact_keys", True),
    )

    signatures_data = data.get("signatures", {})
    signatures = SignatureConfig(
        path=signatures_data.get("path", "/etc/aiproxyguard/signatures"),
    )

    control_plane_data = data.get("control_plane", {})
    control_plane = ControlPlaneConfig(
        enabled=control_plane_data.get("enabled", False),
        url=control_plane_data.get("url", ""),
        api_key=control_plane_data.get("api_key", ""),
        heartbeat_interval=control_plane_data.get("heartbeat_interval", 60),
        sync_signatures=control_plane_data.get("sync_signatures", True),
        report_telemetry=control_plane_data.get("report_telemetry", True),
        manifest_public_key=control_plane_data.get("manifest_public_key", ""),
    )

    tls_data = data.get("tls", {})
    tls = TLSConfig(
        enabled=tls_data.get("enabled", False),
        ca_cert=tls_data.get("ca_cert", "/etc/aiproxyguard/ca.crt"),
        ca_key=tls_data.get("ca_key", "/etc/aiproxyguard/ca.key"),
        cert_cache_size=tls_data.get("cert_cache_size", 1000),
        cert_validity_days=tls_data.get("cert_validity_days", 30),
    )

    identity_data = data.get("identity", {})
    identity = IdentityConfig(
        method=identity_data.get("method", "ip"),
        header_name=identity_data.get("header_name", "X-Client-ID"),
        fallback_header=identity_data.get("fallback_header"),
        trust_xff=identity_data.get("trust_xff", False),
        hash_token=identity_data.get("hash_token", True),
    )

    return Config(
        server=server,
        upstreams=upstreams,
        scanner=scanner,
        policy=policy,
        signatures=signatures,
        security=security,
        metrics=metrics,
        logging=logging,
        control_plane=control_plane,
        tls=tls,
        identity=identity,
    )
