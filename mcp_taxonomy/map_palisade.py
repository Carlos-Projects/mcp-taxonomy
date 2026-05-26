"""Mapper: palisade-scanner Finding → TaxonomyEvent."""

from __future__ import annotations

from mcp_taxonomy.core import (
    AttackCategory,
    Confidence,
    DetectionMethod,
    Severity,
    TaxonomyEvent,
    severity_weight,
)

_PALISADE_CATEGORY_MAP: dict[str, AttackCategory] = {
    "jailbreak": AttackCategory.JAILBREAK,
    "role_override": AttackCategory.IMPERSONATION,
    "exfiltration": AttackCategory.EXFILTRATION,
    "tool_manipulation": AttackCategory.TOOL_POISONING,
    "impersonation": AttackCategory.IMPERSONATION,
    "malware_generation": AttackCategory.MALWARE,
    "policy_puppetry": AttackCategory.POLICY_VIOLATION,
    "claude_trigger": AttackCategory.JAILBREAK,
    "scareware": AttackCategory.SCAREWARE,
    "weaponized_code": AttackCategory.MALWARE,
    "hidden_instruction": AttackCategory.INJECTION,
    "unicode_stego": AttackCategory.UNICODE_ATTACK,
    "unicode_zalgo": AttackCategory.UNICODE_ATTACK,
    "homoglyph_bypass": AttackCategory.HOMOGLYPH,
    "stego_marker": AttackCategory.STEGO,
    "encoded_payload": AttackCategory.ENCODED_PAYLOAD,
    "image_stego": AttackCategory.STEGO,
    "system_error": AttackCategory.ANOMALY,
}

_PALISADE_DETECTOR_MAP: dict[str, DetectionMethod] = {
    "hidden_text": DetectionMethod.HIDDEN_TEXT,
    "injection_patterns": DetectionMethod.INJECTION_PATTERNS,
    "metadata_analyzer": DetectionMethod.METADATA_ANALYZER,
    "exfiltration": DetectionMethod.EXFILTRATION,
    "unicode_advanced": DetectionMethod.UNICODE_ADVANCED,
    "stego_markers": DetectionMethod.STEGO_MARKERS,
    "entropy_analyzer": DetectionMethod.ENTROPY_ANALYZER,
    "image_stego": DetectionMethod.IMAGE_STEGO,
    "instruction_classifier": DetectionMethod.INSTRUCTION_CLASSIFIER,
}

_CONFIDENCE_MAP: dict[float, Confidence] = {
    1.0: Confidence.CERTAIN,
    0.95: Confidence.CERTAIN,
    0.9: Confidence.HIGH,
    0.85: Confidence.HIGH,
    0.8: Confidence.HIGH,
    0.7: Confidence.HIGH,
    0.6: Confidence.MEDIUM,
    0.5: Confidence.MEDIUM,
    0.4: Confidence.MEDIUM,
    0.3: Confidence.LOW,
    0.2: Confidence.LOW,
    0.1: Confidence.LOW,
}


def _confidence_from_float(val: float) -> Confidence:
    for threshold, conf in sorted(_CONFIDENCE_MAP.items(), reverse=True):
        if val >= threshold:
            return conf
    return Confidence.NONE


def palisade_finding_to_taxonomy(finding: dict | object) -> TaxonomyEvent:
    if isinstance(finding, dict):
        category_str = finding.get("category", "")
        detector_str = finding.get("detector", "")
        sev_str = finding.get("severity", "info")
        title = finding.get("title", "")
        desc = finding.get("description", "")
        rec = finding.get("recommendation", "")
        snippet = finding.get("snippet", "")
        conf_val = finding.get("confidence", 0.0)
        target = finding.get("url", "") or finding.get("source_url", "")
        raw = finding
    else:
        category_str = getattr(finding, "category", "")
        detector_str = getattr(finding, "detector", "")
        sev_str = getattr(finding, "severity", "info")
        title = getattr(finding, "title", "")
        desc = getattr(finding, "description", "")
        rec = getattr(finding, "recommendation", "")
        snippet = getattr(finding, "snippet", "")
        conf_val = getattr(finding, "confidence", 0.0)
        target = getattr(finding, "url", "") or getattr(finding, "source_url", "")
        raw = None

    category = _PALISADE_CATEGORY_MAP.get(category_str, AttackCategory.INJECTION)
    detector = _PALISADE_DETECTOR_MAP.get(detector_str, DetectionMethod.INJECTION_PATTERNS)
    severity = Severity(sev_str) if sev_str in {s.value for s in Severity} else Severity.MEDIUM
    confidence = _confidence_from_float(conf_val)

    return TaxonomyEvent(
        source="palisade-scanner",
        attack_category=category,
        severity=severity,
        confidence=confidence,
        detection_method=detector,
        title=title,
        description=desc,
        recommendation=rec,
        snippet=snippet,
        target=target,
        raw=raw,
        risk_score=severity_weight(severity) * int(conf_val * 100) // 25,
    )
