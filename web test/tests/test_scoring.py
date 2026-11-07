"""Pruebas del sistema de puntuación y calificaciones de seguridad."""

from websec.core.models import Finding, Severity
from websec.core.scoring import SecurityScorer


def test_scorer_clean_score() -> None:
    res = SecurityScorer.calculate([])
    assert res.score == 100
    assert res.grade == "A+"


def test_scorer_with_findings() -> None:
    findings = [
        Finding(
            id="1",
            title="Crit",
            module="test",
            severity=Severity.CRITICAL,
            description="desc",
            evidence="ev",
            impact="imp",
            recommendation="rec",
            reference="ref",
        ),
        Finding(
            id="2",
            title="High",
            module="test",
            severity=Severity.HIGH,
            description="desc",
            evidence="ev",
            impact="imp",
            recommendation="rec",
            reference="ref",
        ),
    ]
    res = SecurityScorer.calculate(findings)
    # 100 - 25 - 15 = 60
    assert res.score == 60
    assert res.grade == "C"
    assert res.breakdown[Severity.CRITICAL.value] == 1
    assert res.breakdown[Severity.HIGH.value] == 1


def test_scorer_minimum_zero() -> None:
    many_critical = [
        Finding(
            id=str(i),
            title="Crit",
            module="test",
            severity=Severity.CRITICAL,
            description="desc",
            evidence="ev",
            impact="imp",
            recommendation="rec",
            reference="ref",
        )
        for i in range(10)
    ]
    res = SecurityScorer.calculate(many_critical)
    assert res.score == 0
    assert res.grade == "F"
