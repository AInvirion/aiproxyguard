# AIProxyGuard Signature Library

Detection signatures for LLM security threats.

## Bundles

| File | Category | Signatures | Tier | Description |
|------|----------|------------|------|-------------|
| `prompt_injection.yaml` | prompt_injection | 10 | free | Instruction override, delimiter injection, system prompt extraction |
| `jailbreak.yaml` | jailbreak | 12 | free | DAN mode, persona exploits, restriction bypass |
| `pii.yaml` | pii | 12 | free | SSN, credit cards, credentials, email/phone extraction |
| `child_protection.yaml` | child_protection | 11 | free | Grooming, CSAM requests, exploitation |
| `encoding_evasion.yaml` | encoding_evasion | 14 | free | Base64, hex, unicode, leetspeak bypass |
| `phi.yaml` | phi | 13 | pro | HIPAA-compliant PHI detection |
| `data_exfil.yaml` | data_exfil | 12 | pro | Database dumps, API key extraction |
| `harmful_content.yaml` | harmful_content | 15 | pro | Violence, weapons, drugs, hacking, fraud |

**Total: 99 signatures**

## Profiles

Pre-configured bundles for common use cases:

| Profile | Bundles | Tier |
|---------|---------|------|
| `basic` | prompt_injection, jailbreak, child_protection | free |
| `enterprise` | prompt_injection, jailbreak, pii, data_exfil, encoding_evasion, harmful_content | pro |
| `healthcare` | prompt_injection, jailbreak, pii, phi, data_exfil, harmful_content | enterprise |
| `child_safe` | prompt_injection, jailbreak, child_protection, harmful_content | pro |
| `maximum` | All bundles | enterprise |

## Signature Format

```yaml
signatures:
  - id: "PI-001"           # Unique identifier (category prefix + number)
    name: "Human readable name"
    category: "prompt_injection"
    severity: "high"       # critical, high, medium, low
    patterns:
      - "regex pattern 1"
      - "regex pattern 2"
    action: "block"        # block, warn, log, allow
```

## Severity Levels

| Level | Description |
|-------|-------------|
| `critical` | Immediate threat, always block |
| `high` | Serious threat, recommend blocking |
| `medium` | Potential threat, warn or log |
| `low` | Low risk, typically log only |

## OWASP LLM Top 10 Coverage

| OWASP ID | Category | Coverage |
|----------|----------|----------|
| LLM01:2025 | Prompt Injection | prompt_injection, jailbreak, encoding_evasion |
| LLM05:2025 | Improper Output Handling | harmful_content |
| LLM06:2025 | Sensitive Information Disclosure | pii, phi, data_exfil |
| LLM10:2025 | Unbounded Consumption | data_exfil |

## Adding Signatures

1. Create or edit the appropriate category file
2. Assign a unique ID with the category prefix (e.g., `PI-011` for prompt injection)
3. Test the pattern against the test corpus
4. Run `python scripts/test_proxy.py` to validate

## Data Sources

Signatures are derived from:
- OWASP LLM Top 10 2025
- JailbreakBench
- HackAPrompt competition
- garak vulnerability scanner
- MITRE ATLAS framework
- Academic research (arXiv)

See [GitHub Issue #4](https://github.com/AInvirion/aiproxyguard/issues/4) for monitoring sources.
