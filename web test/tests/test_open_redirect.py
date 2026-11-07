"""Pruebas de Open Redirect con mocks."""

import respx
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.active.open_redirect import OpenRedirectModule


@respx.mock
def test_open_redirect_detected(sample_target: Target, sample_config: ScanConfig) -> None:
    page = CrawledPage(
        url="https://example.com/login?redirect_to=/dashboard",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="<html>Login Form</html>",
    )

    def redirect_responder(request):
        dest = request.url.params.get("redirect_to", "")
        if dest:
            return respx.MockResponse(
                status_code=302,
                headers={"Location": dest},
            )
        return respx.MockResponse(status_code=404)

    respx.get(url__regex=r"https://example\.com/.*").mock(side_effect=redirect_responder)

    with SafeHttpClient(sample_target, sample_config) as client:
        module = OpenRedirectModule()
        findings = module.run(sample_target, client, [page], sample_config)

        assert len(findings) >= 1
        assert any(f.id == "WSA-REDIR-001" for f in findings)
