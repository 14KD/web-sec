"""Pruebas del módulo activo de detección de XSS reflejado con mocks."""

import respx
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.active.xss import XssModule


@respx.mock
def test_xss_reflected_parameter(sample_target: Target, sample_config: ScanConfig) -> None:
    page = CrawledPage(
        url="https://example.com/search?q=apple",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="<html><body>Resultados para apple</body></html>",
    )

    # Simular reflejo no sanitizado
    def xss_side_effect(request):
        q_val = request.url.params.get("q", "")
        return respx.MockResponse(status_code=200, text=f"<html>Resultados para: {q_val}</html>")

    respx.get("https://example.com/search").mock(side_effect=xss_side_effect)

    with SafeHttpClient(sample_target, sample_config) as client:
        module = XssModule()
        findings = module.run(sample_target, client, [page], sample_config)

        assert len(findings) == 1
        assert findings[0].id == "WSA-XSS-001"
