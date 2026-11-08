"""Pruebas de modelos de datos y validaciones de alcance."""

from websec.core.models import Finding, Severity, Target


def test_target_parsing_and_scope() -> None:
    target = Target("example.com")
    assert target.url == "https://example.com"
    assert target.domain == "example.com"
    assert target.scheme == "https"

    # En scope
    assert target.in_scope("https://example.com/about") is True
    assert target.in_scope("/login") is True
    assert target.in_scope("https://other.com") is False

    # Subdominios
    assert target.in_scope("https://api.example.com", allow_subdomains=False) is False
    assert target.in_scope("https://api.example.com", allow_subdomains=True) is True
    assert target.in_scope("https://evil-example.com", allow_subdomains=True) is False


def test_finding_to_dict_and_severity() -> None:
    finding = Finding(
        id="WSA-TEST-001",
        title="Test Finding",
        module="test_module",
        severity=Severity.HIGH,
        description="Descripción de prueba",
        evidence="Header missing",
        impact="Alto impacto",
        recommendation="Solucionar de inmediato",
        reference="https://owasp.org",
        url="https://example.com",
    )

    data = finding.to_dict()
    assert data["id"] == "WSA-TEST-001"
    assert data["severity"] == "Alta"
    assert finding.severity.score_penalty == 15
    assert "red" in finding.severity.color
