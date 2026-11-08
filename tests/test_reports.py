"""Pruebas de generación de reportes (Consola, JSON, HTML, VULNERABILITIES.md)."""

from pathlib import Path
from websec.core.models import Finding, ScanResult, ScanStats, Severity, Target
from websec.core.scoring import SecurityScorer
from websec.reports.console import ConsoleReport
from websec.reports.html_report import HtmlReport
from websec.reports.json_report import JsonReport
from websec.reports.vulnerabilities_report import VulnerabilitiesReport


def test_reports_generation(tmp_path: Path) -> None:
    target = Target("https://test.example.com")
    finding = Finding(
        id="WSA-TEST-001",
        title="Test Insecure Header",
        module="headers",
        severity=Severity.HIGH,
        description="Falta cabecera CSP",
        evidence="Header ausente",
        impact="Riesgo de XSS",
        recommendation="Configurar CSP",
        reference="https://owasp.org",
        url="https://test.example.com",
    )
    score = SecurityScorer.calculate([finding])
    result = ScanResult(
        target=target,
        findings=[finding],
        score=score,
        stats=ScanStats(pages_crawled=1, requests_made=2, duration_seconds=1.5),
        crawled_urls=["https://test.example.com"],
    )

    # 1. Consola
    console_rep = ConsoleReport()
    console_rep.print_banner()
    console_rep.print_results(result)

    # 2. JSON
    json_path = tmp_path / "report.json"
    JsonReport.generate(result, json_path)
    assert json_path.exists()
    assert "test.example.com" in json_path.read_text(encoding="utf-8")

    # 3. HTML
    html_path = tmp_path / "report.html"
    HtmlReport.generate(result, html_path)
    assert html_path.exists()
    content_html = html_path.read_text(encoding="utf-8")
    assert "WSA-TEST-001" in content_html
    assert "Test Insecure Header" in content_html

    # 4. vulnerabilities.json y VULNERABILITIES.md
    vuln_json = tmp_path / "vulnerabilities.json"
    vuln_md = tmp_path / "VULNERABILITIES.md"
    VulnerabilitiesReport.generate_json(result, vuln_json)
    VulnerabilitiesReport.generate_markdown(result, vuln_md)

    assert vuln_json.exists()
    assert "WSA-TEST-001" in vuln_json.read_text(encoding="utf-8")
    assert vuln_md.exists()
    content_md = vuln_md.read_text(encoding="utf-8")
    assert "# Reporte de Vulnerabilidades" in content_md
    assert "### Alta (1)" in content_md
