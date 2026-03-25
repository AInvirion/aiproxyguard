---
title: Security
---

# Security

## Threat Detection

AIProxyGuard detects the following attack categories:

| Category | Description | Action |
|----------|-------------|--------|
| `prompt_injection` | Attempts to override system instructions | Block |
| `jailbreak` | DAN mode, evil mode, persona exploits | Block |
| `pii` | PII extraction attempts | Block |
| `encoding_evasion` | Base64, hex, unicode obfuscation | Block |

## Reporting Vulnerabilities

Please report security vulnerabilities to security@ainvirion.com.

See [SECURITY.md](https://github.com/AInvirion/aiproxyguard/blob/main/SECURITY.md) for our security policy.
