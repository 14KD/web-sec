"""Pruebas de configuraciones inseguras de CORS con mocks."""

import respx
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.active.cors import CorsModule


@respx.mock
def test_cors_origin_reflection_with_credentials(sample_target: Target, sample_config: ScanConfig) -> None:
    page = CrawledPage(
        url="https://example.com/api/user",
        status_code=200,
        headers={"Content-Type": "application/json"},
        body='{"username": "admin"}',
    )

    def cors_responder(request):
        origin = request.headers.get("origin")
        headers = {}
        if origin:
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        return respx.MockResponse(status_code=200, headers=headers, text="OK")

    respx.get("https://example.com/api/user").mock(side_effect=cors_responder)
    respx.get("https://example.com").mock(side_effect=cors_responder)

    with SafeHttpClient(sample_target, sample_config) as client:
        module = CorsModule()
        findings = module.run(sample_target, client, [page], sample_config)

        assert any(f.id == "WSA-CORS-001" for f in findings)
