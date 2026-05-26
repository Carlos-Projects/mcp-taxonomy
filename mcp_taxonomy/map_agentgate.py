"""Mapper: agentgate signal/decision → TaxonomyEvent."""

from __future__ import annotations

from mcp_taxonomy.core import (
    AttackCategory,
    Confidence,
    DetectionMethod,
    Severity,
    TaxonomyEvent,
    severity_weight,
)

_AGENTGATE_SIGNAL_MAP: dict[str, AttackCategory] = {
    "known_ai_user_agent": AttackCategory.CRAWL,
    "suspicious_user_agent": AttackCategory.CRAWL,
    "missing_accept_language": AttackCategory.ANOMALY,
    "missing_cookies": AttackCategory.ANOMALY,
    "high_request_rate": AttackCategory.CRAWL,
    "honeypot_hit": AttackCategory.CRAWL,
    "robots_violation": AttackCategory.CRAWL,
    "no_js_execution": AttackCategory.ANOMALY,
    "datacenter_asn": AttackCategory.CRAWL,
    "repeated_path_pattern": AttackCategory.CRAWL,
    "policy_mismatch": AttackCategory.ANOMALY,
}

_AGENTGATE_ACTION_SEVERITY: dict[str, Severity] = {
    "allow": Severity.INFO,
    "limited": Severity.LOW,
    "challenge": Severity.MEDIUM,
    "sandbox": Severity.HIGH,
    "block": Severity.CRITICAL,
    "log_only": Severity.INFO,
}

_AGENTGATE_SIGNAL_CONFIDENCE: dict[str, float] = {
    "known_ai_user_agent": 0.95,
    "suspicious_user_agent": 0.6,
    "missing_accept_language": 0.4,
    "missing_cookies": 0.3,
    "high_request_rate": 0.85,
    "honeypot_hit": 1.0,
    "robots_violation": 0.8,
    "no_js_execution": 0.5,
    "datacenter_asn": 0.8,
    "repeated_path_pattern": 0.7,
    "policy_mismatch": 0.75,
}


def agentgate_signal_to_taxonomy(
    signal_type: str,
    weight: int = 0,
    action: str = "",
    path: str = "",
    user_agent: str = "",
    score: int = 0,
) -> TaxonomyEvent:
    category = _AGENTGATE_SIGNAL_MAP.get(signal_type, AttackCategory.ANOMALY)
    severity = _AGENTGATE_ACTION_SEVERITY.get(action, Severity.LOW)
    confidence_val = _AGENTGATE_SIGNAL_CONFIDENCE.get(signal_type, 0.5)

    if confidence_val >= 0.9:
        confidence = Confidence.CERTAIN
    elif confidence_val >= 0.7:
        confidence = Confidence.HIGH
    elif confidence_val >= 0.5:
        confidence = Confidence.MEDIUM
    else:
        confidence = Confidence.LOW

    try:
        method = DetectionMethod(signal_type)
    except ValueError:
        method = signal_type

    return TaxonomyEvent(
        source="agentgate",
        attack_category=category,
        severity=severity,
        confidence=confidence,
        detection_method=method,
        title=signal_type.replace("_", " ").title(),
        description=f"Signal: {signal_type}, weight: {weight}, action: {action}",
        target=path,
        snippet=user_agent[:200] if user_agent else "",
        risk_score=score,
    )


def agentgate_log_entry_to_taxonomy(entry: dict) -> TaxonomyEvent | None:
    signal_type = entry.get("signal_type", "") or (entry.get("signals") or [None])[0]
    if not signal_type:
        return None
    return agentgate_signal_to_taxonomy(
        signal_type=signal_type if isinstance(signal_type, str) else "",
        weight=entry.get("weight", 0),
        action=entry.get("action", ""),
        path=entry.get("path", ""),
        user_agent=entry.get("userAgent", ""),
        score=entry.get("score", 0),
    )
