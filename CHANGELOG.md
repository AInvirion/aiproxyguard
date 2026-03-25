# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.12...HEAD
[0.2.12]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.11...v0.2.12
[0.2.11]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.10...v0.2.11
[0.2.10]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/AInvirion/aiproxyguard/compare/v0.2.0...v0.2.7
[0.2.0]: https://github.com/AInvirion/aiproxyguard/releases/tag/v0.2.0
