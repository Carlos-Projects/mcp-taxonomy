"""Mapper: MCPGuard SecurityEvent → TaxonomyEvent."""

from __future__ import annotations

from datetime import UTC

from mcp_taxonomy.core import (
    AttackCategory,
    Confidence,
    DetectionMethod,
    Severity,
    TaxonomyEvent,
    severity_weight,
)

_MCPGUARD_EVENT_TYPE_MAP: dict[str, AttackCategory] = {
    "prompt_injection": AttackCategory.INJECTION,
    "prompt_injection_sse": AttackCategory.INJECTION,
    "jailbreak_pattern": AttackCategory.JAILBREAK,
    "jailbreak_pattern_sse": AttackCategory.JAILBREAK,
    "tool_poisoning": AttackCategory.TOOL_POISONING,
    "tool_poisoning_sse": AttackCategory.TOOL_POISONING,
    "suspicious_resource": AttackCategory.RESOURCE_SCAN,
    "suspicious_resource_sse": AttackCategory.RESOURCE_SCAN,
    "suspicious_prompt": AttackCategory.RESOURCE_SCAN,
    "stego_detection": AttackCategory.STEGO,
    "stego_detection_sse": AttackCategory.STEGO,
    "anomaly": AttackCategory.ANOMALY,
    "rate_limit": AttackCategory.ANOMALY,
    "tool_blocked": AttackCategory.TOOL_POISONING,
    "sse_connect": AttackCategory.ANOMALY,
    "ws_connect": AttackCategory.ANOMALY,
    "message": AttackCategory.ANOMALY,
    "upstream_error": AttackCategory.ANOMALY,
}

_MCPGUARD_PLUGIN_DETECTORS: dict[str, DetectionMethod] = {
    "prompt_injection": DetectionMethod.PROMPT_INJECTION,
    "jailbreak_pattern": DetectionMethod.JAILBREAK_PATTERNS,
    "tool_poisoning": DetectionMethod.TOOL_POISONING,
    "resource_prompt": DetectionMethod.RESOURCE_PROMPT,
    "stego_detector": DetectionMethod.STEGO_DETECTOR,
    "anomaly": DetectionMethod.ANOMALY_DETECTOR,
}


def mcpguard_event_to_taxonomy(event: dict | object) -> TaxonomyEvent:
    if isinstance(event, dict):
        event_type = event.get("event_type", "")
        sev_str = event.get("severity", "info")
        msg = event.get("message", "")
        details = event.get("details", {}) or {}
        has_blocked = "blocked" in event
        blocked_val: bool | None = event.get("blocked") if has_blocked else None
        ts = event.get("timestamp", "")
    else:
        event_type = getattr(event, "event_type", "")
        sev_str = getattr(event, "severity", "info")
        msg = getattr(event, "message", "")
        details = getattr(event, "details", {}) or {}
        has_blocked = hasattr(event, "blocked")
        blocked_val: bool | None = getattr(event, "blocked", None) if has_blocked else None
        ts = getattr(event, "timestamp", "")

    if isinstance(details, dict):
        tool = details.get("tool", "") or details.get("tool_name", "")
        snippet = details.get("content", "") or details.get("arguments", "")
        if isinstance(snippet, dict):
            snippet = str(snippet)
    else:
        tool = ""
        snippet = ""

    category = _MCPGUARD_EVENT_TYPE_MAP.get(event_type, AttackCategory.ANOMALY)

    detector = DetectionMethod.ANOMALY_DETECTOR
    for prefix, method in _MCPGUARD_PLUGIN_DETECTORS.items():
        if event_type.startswith(prefix):
            detector = method
            break

    severity = Severity(sev_str) if sev_str in {s.value for s in Severity} else Severity.MEDIUM

    from datetime import datetime
    return TaxonomyEvent(
        source="mcpguard",
        attack_category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        detection_method=detector,
        title=event_type.replace("_", " ").title(),
        description=msg,
        snippet=str(snippet)[:500],
        target=tool,
        blocked=blocked_val,
        timestamp=ts if ts else datetime.now(UTC).isoformat(),
        raw=details if isinstance(details, dict) else {},
        risk_score=severity_weight(severity) * 10,
    )
