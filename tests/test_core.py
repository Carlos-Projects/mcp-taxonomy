"""Tests for the core taxonomy."""

import pytest
from mcp_taxonomy import (
    AttackCategory,
    Confidence,
    DetectionMethod,
    Severity,
    TaxonomyEvent,
    severity_from_score,
    severity_weight,
)


class TestSeverity:
    def test_order(self) -> None:
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO

    def test_weights(self) -> None:
        assert severity_weight(Severity.CRITICAL) == 25
        assert severity_weight(Severity.HIGH) == 10
        assert severity_weight(Severity.MEDIUM) == 3
        assert severity_weight(Severity.LOW) == 1
        assert severity_weight(Severity.INFO) == 0

    def test_from_score(self) -> None:
        assert severity_from_score(95) == Severity.CRITICAL
        assert severity_from_score(60) == Severity.HIGH
        assert severity_from_score(30) == Severity.MEDIUM
        assert severity_from_score(10) == Severity.LOW
        assert severity_from_score(2) == Severity.INFO


class TestCategories:
    def test_all_categories_have_severity(self) -> None:
        from mcp_taxonomy.core import CATEGORY_SEVERITY
        assert len(CATEGORY_SEVERITY) == len(AttackCategory)
        for cat in AttackCategory:
            assert cat in CATEGORY_SEVERITY, f"Missing severity for {cat}"


class TestConfidence:
    def test_scores(self) -> None:
        assert Confidence.CERTAIN.score == 1.0
        assert Confidence.LOW.score == 0.3
        assert Confidence.NONE.score == 0.0

    def test_ordering(self) -> None:
        scores = [c.score for c in Confidence]
        assert scores == sorted(scores, reverse=True)


class TestTaxonomyEvent:
    def test_create_minimal(self) -> None:
        event = TaxonomyEvent(
            source="test",
            attack_category=AttackCategory.INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            title="Test finding",
        )
        assert event.source == "test"
        assert event.attack_category == AttackCategory.INJECTION
        assert event.severity == Severity.HIGH
        assert event.confidence == Confidence.HIGH
        assert event.title == "Test finding"
        assert event.timestamp is not None

    def test_risk_computed(self) -> None:
        event = TaxonomyEvent(
            source="test",
            attack_category=AttackCategory.MALWARE,
            severity=Severity.CRITICAL,
            confidence=Confidence.CERTAIN,
            title="Critical finding",
            risk_score=95,
        )
        assert event.risk.score == 95
        assert event.risk.severity == Severity.CRITICAL

    def test_all_fields(self) -> None:
        event = TaxonomyEvent(
            source="palisade-scanner",
            attack_category=AttackCategory.STEGO,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            detection_method=DetectionMethod.IMAGE_STEGO,
            title="LSB stego detected",
            description="LSB manipulation in image channel 0",
            recommendation="Review image content",
            target="https://example.com/image.png",
            snippet="Pixel data...",
            raw={"channel": 0, "deviation": 0.15},
            blocked=None,
            risk_score=30,
        )
        assert event.detection_method == DetectionMethod.IMAGE_STEGO
        assert event.raw == {"channel": 0, "deviation": 0.15}
