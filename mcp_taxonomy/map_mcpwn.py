"""Mapper: MCPwn Finding → TaxonomyEvent."""

from __future__ import annotations

from mcp_taxonomy.core import (
    AttackCategory,
    Confidence,
    DetectionMethod,
    Severity,
    TaxonomyEvent,
    severity_weight,
)

_MCPWN_ATTACK_TYPE_MAP: dict[str, AttackCategory] = {
    "command_injection": AttackCategory.CMD_INJECTION,
    "path_traversal": AttackCategory.CMD_INJECTION,
    "prompt_injection_fuzz": AttackCategory.INJECTION,
    "tool_poisoning": AttackCategory.TOOL_POISONING,
    "tool_poisoning_fuzz": AttackCategory.TOOL_POISONING,
    "ssrf": AttackCategory.SSRF,
    "sql_injection": AttackCategory.SQL_INJECTION,
    "rce_blind": AttackCategory.RCE,
    "a2a_misconfiguration": AttackCategory.MISCONFIGURATION,
    "a2a_tool_poisoning": AttackCategory.TOOL_POISONING,
}

_MCPWN_ATTACK_METHOD_MAP: dict[str, DetectionMethod] = {
    "command_injection": DetectionMethod.INJECTION_TESTER,
    "path_traversal": DetectionMethod.INJECTION_TESTER,
    "prompt_injection_fuzz": DetectionMethod.PROMPT_FUZZER,
    "tool_poisoning": DetectionMethod.TOOL_ANALYSIS,
    "tool_poisoning_fuzz": DetectionMethod.TOOL_POISONING_FUZZER,
    "ssrf": DetectionMethod.SSRF_TESTER,
    "sql_injection": DetectionMethod.SQLI_TESTER,
    "rce_blind": DetectionMethod.RCE_BLIND_TESTER,
    "a2a_misconfiguration": DetectionMethod.A2A_SCANNER,
    "a2a_tool_poisoning": DetectionMethod.A2A_SCANNER,
}


def mcpwn_finding_to_taxonomy(finding: dict | object) -> TaxonomyEvent:
    if isinstance(finding, dict):
        attack_type = finding.get("attack_type", "")
        sev_str = finding.get("severity", "info")
        title = finding.get("title", "")
        desc = finding.get("description", "")
        detail = finding.get("detail", "")
        rec = finding.get("recommendation", "")
        target = finding.get("target", "")
        evidence = finding.get("evidence", {}) or {}
    else:
        attack_type = getattr(finding, "attack_type", "")
        sev_str = getattr(finding, "severity", "info")
        title = getattr(finding, "title", "")
        desc = getattr(finding, "description", "")
        detail = getattr(finding, "detail", "")
        rec = getattr(finding, "recommendation", "")
        target = getattr(finding, "target", "")
        evidence = getattr(finding, "evidence", {}) or {}

    category = _MCPWN_ATTACK_TYPE_MAP.get(attack_type, AttackCategory.INJECTION)
    method = _MCPWN_ATTACK_METHOD_MAP.get(attack_type, DetectionMethod.INJECTION_TESTER)
    severity = Severity(sev_str) if sev_str in {s.value for s in Severity} else Severity.MEDIUM

    payload = ""
    if isinstance(evidence, dict):
        payload = evidence.get("payload", "") or evidence.get("response_preview", "")

    return TaxonomyEvent(
        source="mcpwn",
        attack_category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        detection_method=method,
        title=title,
        description=desc or detail,
        recommendation=rec,
        target=target,
        snippet=str(payload)[:500],
        raw=evidence,
        risk_score=severity_weight(severity) * 10,
    )
