"""Pruebas del módulo de Clickjacking."""

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage, FormInfo
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.active.clickjacking import ClickjackingModule


def test_clickjacking_missing_frame_options(sample_target: Target, sample_config: ScanConfig) -> None:
    page = CrawledPage(
        url="https://example.com/transfer",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="<html>Transfer Funds Form</html>",
        forms=[FormInfo(action="/transfer", method="POST")],
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = ClickjackingModule()
        findings = module.run(sample_target, client, [page], sample_config)

        assert len(findings) == 1
        assert findings[0].id == "WSA-CLK-001"


def test_clickjacking_protected_by_csp(sample_target: Target, sample_config: ScanConfig) -> None:
    page = CrawledPage(
        url="https://example.com/transfer",
        status_code=200,
        headers={"Content-Security-Policy": "frame-ancestors 'self'"},
        body="<html>Transfer Funds Form</html>",
        forms=[FormInfo(action="/transfer", method="POST")],
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = ClickjackingModule()
        findings = module.run(sample_target, client, [page], sample_config)

        assert len(findings) == 0
