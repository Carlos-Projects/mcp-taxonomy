"""Tests for RAGuard mapper adapter."""

from mcp_taxonomy import (
    AttackCategory,
    Confidence,
    DetectionMethod,
    Severity,
    raguard_finding_to_taxonomy,
)


class TestRAGuardMapper:
    def test_dict_input(self) -> None:
        event = raguard_finding_to_taxonomy(
            {
                "attack_type": "data_poisoning",
                "detector": "data_poisoning",
                "severity": "high",
                "confidence": "high",
                "title": "Data poisoning detected",
                "description": "Test description",
                "recommendation": "Test recommendation",
                "snippet": "test snippet",
                "target": "http://test.com",
                "risk_score": 75,
            }
        )

        assert event.source == "raguard"
        assert event.attack_category == AttackCategory.DATA_POISONING
        assert event.severity == Severity.HIGH
        assert event.confidence == Confidence.HIGH
        assert event.detection_method == DetectionMethod.DATA_POISONING_DETECTOR
        assert event.title == "Data poisoning detected"
        assert event.risk_score == 75

    def test_membership_inference_mapping(self) -> None:
        event = raguard_finding_to_taxonomy(
            {
                "attack_type": "membership_inference",
                "detector": "membership_inference",
                "severity": "critical",
                "confidence": "certain",
                "title": "Membership inference",
            }
        )

        assert event.attack_category == AttackCategory.MEMBERSHIP_INFERENCE
        assert event.detection_method == DetectionMethod.MEMBERSHIP_INFERENCE_DETECTOR
        assert event.severity == Severity.CRITICAL
        assert event.confidence == Confidence.CERTAIN

    def test_prompt_leakage_mapping(self) -> None:
        event = raguard_finding_to_taxonomy(
            {
                "attack_type": "prompt_leakage",
                "detector": "prompt_leakage",
                "severity": "high",
                "confidence": "high",
                "title": "Prompt leakage",
            }
        )

        assert event.attack_category == AttackCategory.EXFILTRATION
        assert event.detection_method == DetectionMethod.PROMPT_LEAKAGE_DETECTOR

    def test_context_overflow_mapping(self) -> None:
        event = raguard_finding_to_taxonomy(
            {
                "attack_type": "context_overflow",
                "detector": "context_overflow",
                "severity": "medium",
                "confidence": "medium",
                "title": "Context overflow",
            }
        )

        assert event.attack_category == AttackCategory.CONTEXT_OVERFLOW
        assert event.detection_method == DetectionMethod.CONTEXT_OVERFLOW_DETECTOR

    def test_retrieval_hijack_mapping(self) -> None:
        event = raguard_finding_to_taxonomy(
            {
                "attack_type": "retrieval_hijack",
                "detector": "retrieval_hijack",
                "severity": "high",
                "confidence": "high",
                "title": "Retrieval hijack",
            }
        )

        assert event.attack_category == AttackCategory.RETRIEVAL_HIJACK
        assert event.detection_method == DetectionMethod.RETRIEVAL_HIJACK_DETECTOR

    def test_vector_injection_mapping(self) -> None:
        event = raguard_finding_to_taxonomy(
            {
                "attack_type": "vector_injection",
                "detector": "vector_injection",
                "severity": "critical",
                "confidence": "high",
                "title": "Vector injection",
            }
        )

        assert event.attack_category == AttackCategory.VECTOR_INJECTION
        assert event.detection_method == DetectionMethod.VECTOR_INJECTION_DETECTOR

    def test_policy_bypass_mapping(self) -> None:
        event = raguard_finding_to_taxonomy(
            {
                "attack_type": "policy_bypass",
                "detector": "policy_bypass",
                "severity": "high",
                "confidence": "medium",
                "title": "Policy bypass",
            }
        )

        assert event.attack_category == AttackCategory.POLICY_VIOLATION
        assert event.detection_method == DetectionMethod.POLICY_BYPASS_DETECTOR

    def test_unknown_attack_type_defaults_to_anomaly(self) -> None:
        event = raguard_finding_to_taxonomy(
            {
                "attack_type": "unknown_type",
                "detector": "test",
                "severity": "info",
                "confidence": "none",
                "title": "Unknown",
            }
        )

        assert event.attack_category == AttackCategory.ANOMALY

    def test_all_categories_mapped(self) -> None:
        """Verify every RAG attack type maps to a valid category."""
        attack_types = [
            "data_poisoning",
            "membership_inference",
            "prompt_leakage",
            "context_overflow",
            "retrieval_hijack",
            "vector_injection",
            "policy_bypass",
        ]
        for at in attack_types:
            event = raguard_finding_to_taxonomy(
                {
                    "attack_type": at,
                    "detector": at,
                    "severity": "medium",
                    "confidence": "medium",
                    "title": at,
                }
            )
            assert isinstance(event.attack_category, AttackCategory)
