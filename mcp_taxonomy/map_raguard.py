"""Mapper: RAGuard RAGFinding → TaxonomyEvent."""

from __future__ import annotations

from mcp_taxonomy.core import (
    AttackCategory,
    Confidence,
    DetectionMethod,
    Severity,
    TaxonomyEvent,
)

_RAG_ATTACK_MAP: dict[str, AttackCategory] = {
    "data_poisoning": AttackCategory.DATA_POISONING,
    "membership_inference": AttackCategory.MEMBERSHIP_INFERENCE,
    "prompt_leakage": AttackCategory.EXFILTRATION,
    "context_overflow": AttackCategory.CONTEXT_OVERFLOW,
    "retrieval_hijack": AttackCategory.RETRIEVAL_HIJACK,
    "vector_injection": AttackCategory.VECTOR_INJECTION,
    "policy_bypass": AttackCategory.POLICY_VIOLATION,
}

_RAG_DETECTOR_MAP: dict[str, DetectionMethod] = {
    "data_poisoning": DetectionMethod.DATA_POISONING_DETECTOR,
    "membership_inference": DetectionMethod.MEMBERSHIP_INFERENCE_DETECTOR,
    "prompt_leakage": DetectionMethod.PROMPT_LEAKAGE_DETECTOR,
    "context_overflow": DetectionMethod.CONTEXT_OVERFLOW_DETECTOR,
    "retrieval_hijack": DetectionMethod.RETRIEVAL_HIJACK_DETECTOR,
    "vector_injection": DetectionMethod.VECTOR_INJECTION_DETECTOR,
    "policy_bypass": DetectionMethod.POLICY_BYPASS_DETECTOR,
}

_CONFIDENCE_MAP: dict[str, Confidence] = {
    "certain": Confidence.CERTAIN,
    "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM,
    "low": Confidence.LOW,
    "none": Confidence.NONE,
}

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def raguard_finding_to_taxonomy(finding: dict | object) -> TaxonomyEvent:
    """Convert a RAGuard RAGFinding (dict or object) to a TaxonomyEvent."""
    if isinstance(finding, dict):
        attack_type = finding.get("attack_type", "")
        detector = finding.get("detector", "")
        sev_str = finding.get("severity", "info")
        conf_str = finding.get("confidence", "medium")
        title = finding.get("title", "")
        desc = finding.get("description", "")
        rec = finding.get("recommendation", "")
        snippet = finding.get("snippet", "")
        target = finding.get("target", "")
        risk_score = finding.get("risk_score", 0)
        raw = finding
    else:
        attack_type = getattr(finding, "attack_type", "")
        detector = getattr(finding, "detector", "")
        sev_str = getattr(finding, "severity", "info")
        conf_str = getattr(finding, "confidence", "medium")
        title = getattr(finding, "title", "")
        desc = getattr(finding, "description", "")
        rec = getattr(finding, "recommendation", "")
        snippet = getattr(finding, "snippet", "")
        target = getattr(finding, "target", "")
        risk_score = getattr(finding, "risk_score", 0)
        raw = None

    # Normalize enum values
    severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM) if isinstance(sev_str, str) else sev_str
    confidence = (
        _CONFIDENCE_MAP.get(conf_str, Confidence.MEDIUM) if isinstance(conf_str, str) else conf_str
    )

    if isinstance(attack_type, str):
        category = _RAG_ATTACK_MAP.get(attack_type, AttackCategory.ANOMALY)
    else:
        category = getattr(attack_type, "value", AttackCategory.ANOMALY)
        category = _RAG_ATTACK_MAP.get(category, AttackCategory.ANOMALY)

    if isinstance(detector, str):
        detection_method = _RAG_DETECTOR_MAP.get(detector, detector)
    else:
        detection_method = getattr(detector, "value", "")

    return TaxonomyEvent(
        source="raguard",
        attack_category=category,
        severity=severity,
        confidence=confidence,
        detection_method=detection_method,
        title=title,
        description=desc,
        recommendation=rec,
        snippet=snippet[:200],
        target=target,
        raw=raw,
        risk_score=risk_score,
    )
