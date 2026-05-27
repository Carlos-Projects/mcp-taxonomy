# mcp-taxonomy

[![CI](https://github.com/Carlos-Projects/mcp-taxonomy/actions/workflows/publish.yml/badge.svg)](https://github.com/Carlos-Projects/mcp-taxonomy/actions/workflows/publish.yml)
[![PyPI](https://img.shields.io/badge/PyPI-mcp--taxonomy-blue?logo=pypi)](https://pypi.org/project/mcp-taxonomy/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230.svg)](https://docs.astral.sh/ruff/)

Canonical classification taxonomy for the MCP security ecosystem.

Provides shared enums, types, and cross-project adapters so findings from
**palisade-scanner**, **MCPGuard**, **MCPwn**, and **agentgate** can be
correlated, compared, and displayed in a unified view (MCPscop).

## Quick Start

```python
from mcp_taxonomy import (
    AttackCategory, Severity, Confidence, DetectionMethod,
    palisade_finding_to_taxonomy,
    mcpguard_event_to_taxonomy,
    mcpwn_finding_to_taxonomy,
    agentgate_signal_to_taxonomy,
)

# Normalize findings from any tool into a common TaxonomyEvent
event = palisade_finding_to_taxonomy({
    "category": "jailbreak",
    "detector": "injection_patterns",
    "severity": "high",
    "confidence": 0.9,
    "title": "Jailbreak detected",
})

print(event.attack_category)  # AttackCategory.JAILBREAK
print(event.severity)         # Severity.HIGH
print(event.source)           # "palisade-scanner"
```

## Taxonomy

### Attack Categories (20)
| Category | Default Severity |
|---|---|
| `rce` | critical |
| `command_injection` | critical |
| `sql_injection` | critical |
| `malware` | critical |
| `exfiltration` | high |
| `tool_poisoning` | high |
| `ssrf` | high |
| `jailbreak` | high |
| `injection` | high |
| `scareware` | high |
| `policy_violation` | medium |
| `impersonation` | medium |
| `stego` | medium |
| `resource_scan` | medium |
| `unicode_attack` | medium |
| `encoded_payload` | medium |
| `anomaly` | medium |
| `crawl` | low |
| `homoglyph` | low |
| `misconfiguration` | low |

### Severity (5 levels)
critical (25) > high (10) > medium (3) > low (1) > info (0)

### Detection Methods (22)
Hidden text, injection patterns, metadata, exfiltration, unicode advanced,
stego markers, entropy, image stego, instruction classifier (palisade-scanner),
prompt injection, jailbreak patterns, tool poisoning, resource prompt,
stego detector, anomaly detector (MCPGuard), injection tester, prompt fuzzer,
tool analysis, tool poisoning fuzzer, SSRF tester, SQLi tester, RCE blind
tester, A2A scanner (MCPwn), known/suspicious UA, rate/honeypot (agentgate).

## Adapters

| Function | Input | Source |
|---|---|---|
| `palisade_finding_to_taxonomy()` | `dict` or `Finding` object | palisade-scanner |
| `mcpguard_event_to_taxonomy()` | `dict` or `SecurityEvent` | MCPGuard |
| `mcpwn_finding_to_taxonomy()` | `dict` or `Finding` object | MCPwn |
| `agentgate_signal_to_taxonomy()` | signal type + metadata | agentgate |

## Development

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
ruff check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Security

Found a vulnerability? See [SECURITY.md](SECURITY.md).
