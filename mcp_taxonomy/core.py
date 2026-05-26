"""Core taxonomy enums, types, and utilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, ClassVar

# ─── Severity ──────────────────────────────────────────────────────────


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __gt__(self, other: Severity) -> bool:
        order = [s.value for s in Severity]
        return order.index(self.value) < order.index(other.value)

    def __lt__(self, other: Severity) -> bool:
        order = [s.value for s in Severity]
        return order.index(self.value) > order.index(other.value)

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS[self]


SEVERITY_ORDER = [s for s in Severity]


def severity_weight(sev: Severity) -> int:
    return SEVERITY_WEIGHTS[sev]


SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def severity_from_score(score: int) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 50:
        return Severity.HIGH
    if score >= 20:
        return Severity.MEDIUM
    if score >= 5:
        return Severity.LOW
    return Severity.INFO


# ─── Attack Categories ────────────────────────────────────────────────


class AttackCategory(str, Enum):
    INJECTION = "injection"
    JAILBREAK = "jailbreak"
    EXFILTRATION = "exfiltration"
    TOOL_POISONING = "tool_poisoning"
    IMPERSONATION = "impersonation"
    RESOURCE_SCAN = "resource_scan"
    ANOMALY = "anomaly"
    STEGO = "stego"
    ENCODED_PAYLOAD = "encoded_payload"
    SCAREWARE = "scareware"
    MALWARE = "malware"
    POLICY_VIOLATION = "policy_violation"
    UNICODE_ATTACK = "unicode_attack"
    HOMOGLYPH = "homoglyph"
    CMD_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    SSRF = "ssrf"
    RCE = "rce"
    CRAWL = "crawl"
    MISCONFIGURATION = "misconfiguration"

    # RAG-specific
    DATA_POISONING = "data_poisoning"
    MEMBERSHIP_INFERENCE = "membership_inference"
    CONTEXT_OVERFLOW = "context_overflow"
    RETRIEVAL_HIJACK = "retrieval_hijack"
    VECTOR_INJECTION = "vector_injection"


CATEGORY_SEVERITY: dict[AttackCategory, Severity] = {
    AttackCategory.RCE: Severity.CRITICAL,
    AttackCategory.CMD_INJECTION: Severity.CRITICAL,
    AttackCategory.SQL_INJECTION: Severity.CRITICAL,
    AttackCategory.MALWARE: Severity.CRITICAL,
    AttackCategory.SCAREWARE: Severity.HIGH,
    AttackCategory.EXFILTRATION: Severity.HIGH,
    AttackCategory.TOOL_POISONING: Severity.HIGH,
    AttackCategory.SSRF: Severity.HIGH,
    AttackCategory.JAILBREAK: Severity.HIGH,
    AttackCategory.INJECTION: Severity.HIGH,
    AttackCategory.POLICY_VIOLATION: Severity.MEDIUM,
    AttackCategory.IMPERSONATION: Severity.MEDIUM,
    AttackCategory.STEGO: Severity.MEDIUM,
    AttackCategory.RESOURCE_SCAN: Severity.MEDIUM,
    AttackCategory.UNICODE_ATTACK: Severity.MEDIUM,
    AttackCategory.ENCODED_PAYLOAD: Severity.MEDIUM,
    AttackCategory.ANOMALY: Severity.MEDIUM,
    AttackCategory.CRAWL: Severity.LOW,
    AttackCategory.HOMOGLYPH: Severity.LOW,
    AttackCategory.MISCONFIGURATION: Severity.LOW,
    # RAG-specific
    AttackCategory.DATA_POISONING: Severity.HIGH,
    AttackCategory.MEMBERSHIP_INFERENCE: Severity.HIGH,
    AttackCategory.CONTEXT_OVERFLOW: Severity.MEDIUM,
    AttackCategory.RETRIEVAL_HIJACK: Severity.HIGH,
    AttackCategory.VECTOR_INJECTION: Severity.CRITICAL,
}


# ─── Detection Methods ────────────────────────────────────────────────


class DetectionMethod(str, Enum):
    """Normalised detector / plugin names across all projects."""

    # palisade-scanner
    HIDDEN_TEXT = "hidden_text"
    INJECTION_PATTERNS = "injection_patterns"
    METADATA_ANALYZER = "metadata_analyzer"
    EXFILTRATION = "exfiltration"
    UNICODE_ADVANCED = "unicode_advanced"
    STEGO_MARKERS = "stego_markers"
    ENTROPY_ANALYZER = "entropy_analyzer"
    IMAGE_STEGO = "image_stego"
    INSTRUCTION_CLASSIFIER = "instruction_classifier"

    # MCPGuard
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_PATTERNS = "jailbreak_patterns"
    TOOL_POISONING = "tool_poisoning"
    RESOURCE_PROMPT = "resource_prompt"
    STEGO_DETECTOR = "stego_detector"
    ANOMALY_DETECTOR = "anomaly_detector"

    # MCPwn
    SURVEY = "survey"
    INJECTION_TESTER = "injection_tester"
    PROMPT_FUZZER = "prompt_fuzzer"
    TOOL_ANALYSIS = "tool_analysis"
    TOOL_POISONING_FUZZER = "tool_poisoning_fuzzer"
    SSRF_TESTER = "ssrf_tester"
    SQLI_TESTER = "sqli_tester"
    RCE_BLIND_TESTER = "rce_blind_tester"
    A2A_SCANNER = "a2a_scanner"

    # agentgate
    KNOWN_AI_UA = "known_ai_user_agent"
    SUSPICIOUS_UA = "suspicious_user_agent"
    MISSING_ACCEPT_LANG = "missing_accept_language"
    MISSING_COOKIES = "missing_cookies"
    HIGH_REQUEST_RATE = "high_request_rate"
    HONEYPOT_HIT = "honeypot_hit"
    ROBOTS_VIOLATION = "robots_violation"
    NO_JS_EXECUTION = "no_js_execution"
    DATACENTER_ASN = "datacenter_asn"
    REPEATED_PATH = "repeated_path_pattern"
    POLICY_MISMATCH = "policy_mismatch"

    # RAGuard
    DATA_POISONING_DETECTOR = "data_poisoning_detector"
    MEMBERSHIP_INFERENCE_DETECTOR = "membership_inference_detector"
    PROMPT_LEAKAGE_DETECTOR = "prompt_leakage_detector"
    CONTEXT_OVERFLOW_DETECTOR = "context_overflow_detector"
    RETRIEVAL_HIJACK_DETECTOR = "retrieval_hijack_detector"
    VECTOR_INJECTION_DETECTOR = "vector_injection_detector"
    POLICY_BYPASS_DETECTOR = "policy_bypass_detector"


# ─── Confidence ────────────────────────────────────────────────────────


class Confidence(str, Enum):
    CERTAIN = "certain"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

    @property
    def score(self) -> float:
        return CONFIDENCE_SCORES[self]


CONFIDENCE_SCORES: dict[Confidence, float] = {
    Confidence.CERTAIN: 1.0,
    Confidence.HIGH: 0.85,
    Confidence.MEDIUM: 0.6,
    Confidence.LOW: 0.3,
    Confidence.NONE: 0.0,
}


# ─── Risk Score ────────────────────────────────────────────────────────


@dataclass
class RiskScore:
    score: int
    severity: Severity

    def __post_init__(self) -> None:
        self.score = max(0, min(100, self.score))
        self.severity = severity_from_score(self.score)

    CATEGORY_THRESHOLDS: ClassVar[dict[Severity, int]] = {
        Severity.CRITICAL: 80,
        Severity.HIGH: 50,
        Severity.MEDIUM: 20,
        Severity.LOW: 5,
        Severity.INFO: 0,
    }


# ─── Canonical Event ──────────────────────────────────────────────────


@dataclass
class TaxonomyEvent:
    """Unified representation of any security finding across the ecosystem."""

    source: str
    attack_category: AttackCategory
    severity: Severity
    confidence: Confidence
    title: str
    description: str = ""
    recommendation: str = ""
    detection_method: DetectionMethod | str = ""
    target: str = ""
    snippet: str = ""
    raw: dict[str, Any] | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    blocked: bool | None = None
    risk_score: int = 0

    @property
    def risk(self) -> RiskScore:
        return RiskScore(score=self.risk_score, severity=self.severity)
