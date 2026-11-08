"""Pruebas del orquestador central del escáner."""

import pytest
import respx
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.core.scanner import SecurityScanner
from websec.modules.base import BaseModule


class DummyModule(BaseModule):
    name = "dummy"
    description = "Dummy test module"
    category = "passive"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: list[CrawledPage],
        config: ScanConfig,
    ) -> list[Finding]:
        return [
            Finding(
                id="WSA-DUMMY-001",
                title="Dummy Finding",
                module=self.name,
                severity=Severity.LOW,
                description="Dummy desc",
                evidence="Dummy ev",
                impact="Dummy imp",
                recommendation="Dummy rec",
                reference="https://example.com",
            )
        ]


def test_scanner_requires_permission() -> None:
    config = ScanConfig(target_url="https://example.com", has_permission=False)
    scanner = SecurityScanner(config)
    with pytest.raises(PermissionError):
        scanner.run()


@respx.mock
def test_scanner_executes_registered_modules(sample_config: ScanConfig) -> None:
    respx.get("https://example.com").respond(status_code=200, headers={"Content-Type": "text/html"}, text="<html>OK</html>")

    scanner = SecurityScanner(sample_config)
    scanner.register_module(DummyModule())

    result = scanner.run()
    assert len(result.findings) == 1
    assert result.findings[0].id == "WSA-DUMMY-001"
    assert result.score is not None
    assert result.score.score == 97  # 100 - 3 (LOW)
