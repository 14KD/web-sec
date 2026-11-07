"""Pruebas de fingerprinting de tecnologías y comparación con CVEs."""

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.passive.tech_fingerprint import TechFingerprintModule


def test_tech_fingerprint_vulnerable_jquery(sample_target: Target, sample_config: ScanConfig) -> None:
    html = """
    <html>
      <head>
        <meta name="generator" content="WordPress 5.8">
        <script src="/js/jquery-3.4.1.min.js"></script>
      </head>
      <body></body>
    </html>
    """
    page = CrawledPage(
        url="https://example.com",
        status_code=200,
        headers={"X-Powered-By": "PHP/7.4.3"},
        body=html,
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = TechFingerprintModule()
        findings = module.run(sample_target, client, [page], sample_config)

        # Debe detectar jQuery vulnerable y WordPress vulnerable, más el reporte informativo
        finding_ids = {f.id for f in findings}
        assert any("CVE" in fid for fid in finding_ids)
        assert "WSA-TECH-001" in finding_ids
