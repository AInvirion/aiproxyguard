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
class MLClassifierConfig:
    """ML classifier configuration."""

    enabled: bool = False
    model_path: str | None = None  # Path to the model file (.joblib, .pkl, .onnx)
    threshold: float = 0.7  # Minimum confidence to trigger detection
    action: str = "block"  # Action when ML detects threat: block, warn, log


@dataclass
class ScannerConfig:
    """Scanner configuration."""

    enabled: bool = True
    # Whether inbound proxied requests are scanned. Distinct from ``enabled``
    # (the global on/off): toggling this off via the policy ``scan_request``
    # flag stops scanning proxied traffic while leaving the manual ``/check``
    # detection endpoint and the global switch untouched.
    request_scanning: bool = True
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
    max_request_size: int = 10 * 1024 * 1024  # 10 MB default
    max_response_size: int = 50 * 1024 * 1024  # 50 MB default
    expose_details: bool = False  # Never expose signature patterns to clients


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
    report_usage: bool = True  # Per-request billed-token usage events on allowed requests
    manifest_public_key: str = ""  # Ed25519 public key (base64) for manifest verification
    cache_mode: str = "full"  # "full", "encrypted_only", "none"


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
class CostOptimizationConfig:
    """Token-cost-optimization features (opt-in, runtime-toggleable).

    Pushed from the control plane via the ``cost_optimization`` config section.
    """

    # Inject cache_control into Anthropic top-level system prompts (#304).
    anthropic_prompt_cache: bool = False


@dataclass
class RoutingConfig:
    """Smart model-routing config (#305), pushed via the ``routing`` section.

    ``tasks`` maps a task name to its served config: an ``ordered_pool``
    (cheapest-first, already resolved by the control plane) and an optional
    ``fallback`` list. ``downgrades`` and ``dry_run`` drive phase-1b transparent
    downgrades (consumed in a later phase); ``dry_run`` defaults True so a
    transparent downgrade never rewrites a model until explicitly enabled.
    """

    tasks: dict[str, Any] = field(default_factory=dict)
    downgrades: list[Any] = field(default_factory=list)
    dry_run: bool = True


@dataclass
class Config:
    """Root configuration."""

    server: ServerConfig
    upstreams: dict[str, UpstreamConfig]
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    ml_classifier: MLClassifierConfig = field(default_factory=MLClassifierConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    signatures: SignatureConfig = field(default_factory=SignatureConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    control_plane: ControlPlaneConfig = field(default_factory=ControlPlaneConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    identity: IdentityConfig = field(default_factory=IdentityConfig)
    cost_optimization: CostOptimizationConfig = field(default_factory=CostOptimizationConfig)
    routing: RoutingConfig = field(default_factory=RoutingConfig)


ENV_VAR_PATTERN = re.compile(r"\$\{([^}:]+)(?::-([^}]*))?\}")


def _substitute_env_vars(value: str) -> str:
    """Substitute ${VAR} and ${VAR:-default} patterns."""

    def replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        default = match.group(2)
        return os.environ.get(var_name, default if default is not None else "")

    return ENV_VAR_PATTERN.sub(replace, value)


def _to_bool(value: Any, default: bool = False) -> bool:
    """Convert value to boolean, handling string representations."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ("true", "1", "yes", "on")
    return default


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

    if raw is None:
        raise ValueError(f"Config file is empty: {path}")
    if not isinstance(raw, dict):
        raise ValueError(f"Config file must be a YAML mapping, got {type(raw).__name__}: {path}")

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
        request_scanning=scanner_data.get("request_scanning", True),
        regex=scanner_data.get("regex", True),
        heuristics=scanner_data.get("heuristics", True),
        ml_classifier=scanner_data.get("ml_classifier", False),
        response=response_config,
    )

    ml_classifier_data = data.get("ml_classifier", {})
    ml_classifier = MLClassifierConfig(
        enabled=ml_classifier_data.get("enabled", False),
        model_path=ml_classifier_data.get("model_path"),
        threshold=ml_classifier_data.get("threshold", 0.7),
        action=ml_classifier_data.get("action", "block"),
    )

    security_data = data.get("security", {})
    security = SecurityConfig(
        failure_mode=security_data.get("failure_mode", "open"),
        scanner_timeout_ms=security_data.get("scanner_timeout_ms", 100),
        upstream_timeout_s=security_data.get("upstream_timeout_s", 60),
        max_request_size=security_data.get("max_request_size", 10 * 1024 * 1024),
        max_response_size=security_data.get("max_response_size", 50 * 1024 * 1024),
        expose_details=security_data.get("expose_details", False),
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
        enabled=_to_bool(control_plane_data.get("enabled", False)),
        url=control_plane_data.get("url", ""),
        api_key=control_plane_data.get("api_key", ""),
        heartbeat_interval=control_plane_data.get("heartbeat_interval", 60),
        sync_signatures=_to_bool(control_plane_data.get("sync_signatures", True), default=True),
        report_telemetry=_to_bool(control_plane_data.get("report_telemetry", True), default=True),
        report_usage=_to_bool(control_plane_data.get("report_usage", True), default=True),
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

    cost_opt_data = data.get("cost_optimization", {})
    cost_optimization = CostOptimizationConfig(
        anthropic_prompt_cache=_to_bool(
            cost_opt_data.get("anthropic_prompt_cache", False), default=False
        ),
    )

    routing_data = data.get("routing", {}) or {}
    routing = RoutingConfig(
        tasks=routing_data.get("tasks", {}) or {},
        downgrades=routing_data.get("downgrades", []) or [],
        dry_run=_to_bool(routing_data.get("dry_run", True), default=True),
    )

    return Config(
        server=server,
        upstreams=upstreams,
        scanner=scanner,
        ml_classifier=ml_classifier,
        policy=policy,
        signatures=signatures,
        security=security,
        metrics=metrics,
        logging=logging,
        control_plane=control_plane,
        tls=tls,
        identity=identity,
        cost_optimization=cost_optimization,
        routing=routing,
    )
