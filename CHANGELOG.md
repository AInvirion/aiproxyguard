# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.50] - 2026-06-10

### Changed
- **Unified HTTP and TLS forwarding into a shared request pipeline** - `server.py` and `tls_proxy.py` previously implemented forwarding independently and had diverged. Both now use a single transport-agnostic pipeline (parse → mutate → serialize → scan → forward → scan response), so the scanner always inspects the exact bytes forwarded upstream.
- TLS-intercept proxy now resolves per-upstream `auth_header` and `timeout` by hostname instead of a fixed header allowlist and the global timeout. Exactly one auth header is forwarded on both paths.
- Fleet registration and heartbeat metadata now report deployment mode (`http`/`tls`).

### Fixed
- **TLS-intercept mode now reports detections to the control plane** - block, warn, and response detections (including model and token telemetry) were silently dropped on the TLS path, making TLS-mode instances invisible in cloud telemetry and savings dashboards.
- Plain HTTP (non-CONNECT) requests through the TLS proxy now enforce the same upstream host allowlist as CONNECT, closing an open-proxy gap.
- Response-scanner timeout in `failure_mode=closed` now blocks the response on both proxy paths (the HTTP path previously failed open).

## [0.2.42] - 2026-04-03

### Fixed
- **Hyperscan large pattern support** - Removed `SOM_LEFTMOST` flag to allow patterns with large quantifiers (`.{0,50}` etc). Trade-off: match start position is estimated (100 chars before end) instead of exact. Full detection accuracy preserved.

## [0.2.41] - 2026-04-03

### Fixed
- **Hyperscan API compatibility** - Updated to use `Database.scan()` directly instead of deprecated `Scanner` class. Fixed detection check to verify `Database.compile/scan` methods exist.
- **Runtime lib installation** - Install `libhyperscan5` and `libre2-*` via apt in final Docker stage with dynamic version detection.

## [0.2.40] - 2026-04-03

### Fixed
- **Docker image missing regex engine libs** - Copy `libre2`/`libhs` shared libs directly from builder stage instead of installing version-specific runtime packages. Fixes 100% CPU and scanner timeouts caused by fallback to Python `re`.

## [0.2.39] - 2026-04-03

### Fixed
- **Docker image missing regex engine libs** (incomplete) - Added build deps but runtime package names varied by Debian version.

## [0.2.38] - 2026-04-02

### Changed
- **Signatures updated to v1.4.3** - Latest detection rules from aiproxyguard-signatures
- Documentation for `/check` endpoint, rate limiting, and sensitivity parameter
- Updated README with detection-only mode example

## [0.2.37] - 2026-04-02

### Added
- **`POST /check` endpoint** - Detection-only scanning without LLM forwarding
  - Returns `{action, category, signature_name, confidence}`
  - Honors `failure_mode` configuration
  - Validates JSON body structure
- **Sensitivity parameter** - Intuitive alternative to threshold (`sensitivity = 1 - threshold`)
  - Higher sensitivity = more strict detection
  - Takes precedence when both threshold and sensitivity are provided
  - Values clamped to [0.0, 1.0] range
- **Rate limiting** - iptables-based DDoS protection (`deploy/rate-limit.sh`)
  - Per-IP rate limiting with hashlimit module
  - Environment variables: `RATE_LIMIT_ENABLED`, `RATE_LIMIT_PORT`, `RATE_LIMIT_RATE`, `RATE_LIMIT_BURST`, `RATE_LIMIT_CONN`, `RATE_LIMIT_WHITELIST`, `RATE_LIMIT_BLOCKLIST`
  - Uses DOCKER-USER chain for Docker compatibility
- **Encoding evasion detection improvements**
  - Zero-width character detection and stripping
  - Hex escape sequence decoding (`\x69` → `i`)
  - ROT13 detection (with noise tolerance)
  - Character insertion detection (emoji, punctuation)
- Root endpoint (`GET /`) returning service name and version

### Fixed
- `/check` endpoint now returns 400 for non-object JSON bodies (arrays, strings)

## [0.2.36] - 2026-03-31

### Added
- Root endpoint returning service name and version

## [0.2.35] - 2026-03-31

### Fixed
- Pass API key header when downloading free tier bundles

## [0.2.34] - 2026-03-31

### Added
- Version check in docker-publish workflow

## [0.2.33] - 2026-03-30

### Fixed
- Correct version reporting in Docker deployments for control plane registration

## [0.2.32] - 2026-03-30

### Security
- **Instance-bound licenses**: Licenses now include `bound_instance_id` to prevent DEK/signature theft
- **Secure cache modes**: New `cache_mode` config option (`full`, `encrypted_only`, `none`)
  - `full`: Default, stores encrypted bundle and DEK for offline use
  - `encrypted_only`: Stores bundle but requires online license refresh for DEK
  - `none`: In-memory only, no disk caching
- **License refresh**: Automatic DEK refresh when using `encrypted_only` mode

### Added
- Instance binding validation in `is_license_valid()`
- `cache_mode` option in `ControlPlaneConfig`
- License refresh flow for cached bundles without DEK

## [0.2.31] - 2026-03-30

### Fixed
- Propagate model metadata through ML model loading chain

## [0.2.30] - 2026-03-30

### Fixed
- Add `brotli` dependency for decoding brotli-compressed responses from OpenAI API

## [Unreleased]

### Added
- ML classifier module for semantic prompt classification (Phase 1)
  - `MLClassifier` class with pluggable backend architecture
  - `SklearnBackend` for scikit-learn models (.joblib, .pkl, .pickle)
  - `MLClassifierConfig` for model path, threshold, and action settings
  - Integration with `ScannerPipeline` for seamless detection
  - Unit tests for classifier and sklearn backend (24 tests)
- Model encryption and licensing (Phase 3)
  - AES-256-GCM encryption for ML models
  - Time-limited licenses with Ed25519 signatures
  - License validation and model decryption in proxy
  - Unit tests for license module (9 tests)
- Proxy-cloud ML model sync (Phase 4)
  - `ControlPlaneClient.sync_ml_model()` for automatic model download
  - License caching with automatic refresh on expiration
  - `MLClassifier.load_from_bytes()` for dynamic model loading
  - Support for both encrypted and unencrypted models
- ONNX Runtime backend for Enterprise tier (Phase 5)
  - `ONNXBackend` for transformer models (.onnx)
  - Automatic softmax normalization for logit outputs
  - `load_from_bytes()` for dynamic model loading
  - Unit tests with graceful handling when onnxruntime not installed (7 tests)
- Production hardening with metrics (Phase 6)
  - `MLClassifierMetrics` class for Prometheus-compatible metrics
  - Prediction counters by category and action (block/allow)
  - Model load tracking with success/failure counts
  - License refresh monitoring with expiration countdown
  - Latency percentiles (p50, p90, p99) with rolling window
  - `MLClassifier.health_check()` for monitoring integration
  - Unit tests for metrics module (15 tests)

## [0.2.12] - 2026-03-25

### Added
- DigitalOcean App Platform deployment spec (`do-app.yaml`)
- Comprehensive documentation site with Jekyll RTD theme
- DigitalOcean deployment guide (`docs/digitalocean-guide.md`)
- Example configuration file (`config.example.yaml`)
- Response scanning for TLS proxy
- Scanner timeout support (`scanner_timeout_ms` config)
- Test coverage for control plane, verifier, and decoder modules (118→165 tests)
- Default Docker configuration (`config.docker.yaml`)
- Prompt injection signatures (PI-001 to PI-003)

### Changed
- Scanner now uses O(n) single-pass best-match tracking instead of O(n log n) sort
- Decoder uses lightweight `count_base64_segments()` and `has_url_encoding()` to reduce memory
- Documentation completely rewritten with accurate feature status

### Fixed
- `scanner_timeout_ms` config now properly applies to request and response scanning
- Empty/invalid YAML config files now show clear error messages
- `auth_header` config option now honored when forwarding to upstream
- Test fixtures use dedicated signatures directory

### Security
- Removed hardcoded API key from `config.test.yaml`

## [0.2.11] - 2026-03-25

### Fixed
- Updated Ed25519 public key in `fetch-signatures.sh` for new keypair

## [0.2.10] - 2026-03-25

### Changed
- Certificate cache now uses `OrderedDict` for O(1) LRU operations (was O(n))

## [0.2.9] - 2026-03-25

### Fixed
- Buffered streaming mode now releases chunks immediately after initial scan passes
- Handle missing `category` field in signatures for backwards compatibility

## [0.2.8] - 2026-03-25

### Changed
- Regex scanning now runs in thread pool to avoid blocking async event loop

### Fixed
- Updated Ed25519 public key for signature verification

## [0.2.7] - 2026-03-25

### Security
- **CRITICAL**: Signature patterns no longer leaked in error responses
- **CRITICAL**: Request/response size limits prevent DoS via unbounded buffering
- **CRITICAL**: Client identity spoofing via headers now prevented (X-Forwarded-For requires explicit trust)
- **CRITICAL**: Manifests now cryptographically verified with Ed25519 signatures

### Fixed
- `/metrics` endpoint now respects `enabled: false` config

## [0.2.0] - 2026-03-24

### Added
- Initial open source release
- Multi-provider routing (OpenAI, Anthropic, OpenRouter, Ollama)
- Request scanning with regex and heuristics
- Response scanning for PII/sensitive data
- Policy engine with per-category actions
- Prometheus metrics endpoint
- Structured JSON logging with key redaction
- Control plane integration (beta)
- TLS interception proxy (beta)
- Ed25519 signature verification for manifests
- Health endpoints (`/healthz`, `/readyz`)

### Security
- API keys never logged or sent to control plane
- Signatures cryptographically verified
- Manifest sequence numbers prevent rollback attacks

[Unreleased]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.50...HEAD
[0.2.50]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.48...v0.2.50
[0.2.38]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.37...v0.2.38
[0.2.37]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.36...v0.2.37
[0.2.36]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.35...v0.2.36
[0.2.35]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.34...v0.2.35
[0.2.34]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.33...v0.2.34
[0.2.33]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.32...v0.2.33
[0.2.32]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.31...v0.2.32
[0.2.31]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.30...v0.2.31
[0.2.30]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.12...v0.2.30
[0.2.12]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.11...v0.2.12
[0.2.11]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.10...v0.2.11
[0.2.10]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.0...v0.2.7
[0.2.0]: https://github.com/AInvirion/aiproxyguard/releases/tag/v0.2.0
