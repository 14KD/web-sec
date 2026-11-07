"""Pruebas del módulo heurístico de SQL Injection con mocks."""

import respx
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.active.sqli import SqliModule


@respx.mock
def test_sqli_error_heuristic(sample_target: Target, sample_config: ScanConfig) -> None:
    page = CrawledPage(
        url="https://example.com/item?id=10",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="<html>Item 10 details</html>",
    )

    def sqli_response(request):
        id_val = request.url.params.get("id", "")
        if "'" in id_val:
            return respx.MockResponse(
                status_code=500,
                text="Fatal error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            )
        return respx.MockResponse(status_code=200, text="Item details")

    respx.get("https://example.com/item").mock(side_effect=sqli_response)

    with SafeHttpClient(sample_target, sample_config) as client:
        module = SqliModule()
        findings = module.run(sample_target, client, [page], sample_config)

        assert len(findings) == 1
        assert findings[0].id == "WSA-SQLI-001"
        assert "MySQL" in findings[0].title
