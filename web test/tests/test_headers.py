"""Pruebas del módulo pasivo de cabeceras de seguridad."""

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Severity, Target
from websec.modules.passive.headers import HeadersModule


def test_headers_missing_all(sample_target: Target, sample_config: ScanConfig) -> None:
    page = CrawledPage(
        url="https://example.com",
        status_code=200,
        headers={"Server": "Apache/2.4.41 (Ubuntu)", "X-Powered-By": "PHP/7.4.3"},
        body="<html>Hello</html>",
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = HeadersModule()
        findings = module.run(sample_target, client, [page], sample_config)

        finding_ids = {f.id for f in findings}
        assert "WSA-HDR-001" in finding_ids  # Missing CSP
        assert "WSA-HDR-003" in finding_ids  # Missing HSTS
        assert "WSA-HDR-004" in finding_ids  # Missing X-Frame-Options
        assert "WSA-HDR-005" in finding_ids  # Missing X-Content-Type-Options
        assert "WSA-HDR-008" in finding_ids  # Server version disclosure
        assert "WSA-HDR-009" in finding_ids  # X-Powered-By disclosure


def test_headers_safe(sample_target: Target, sample_config: ScanConfig) -> None:
    safe_headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=(), microphone=()",
    }
    page = CrawledPage(
        url="https://example.com",
        status_code=200,
        headers=safe_headers,
        body="<html>Hello</html>",
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = HeadersModule()
        findings = module.run(sample_target, client, [page], sample_config)
        assert len(findings) == 0
