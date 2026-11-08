"""Pruebas del módulo activo de detección de XSS reflejado con mocks."""

import html
from unittest.mock import MagicMock

import respx
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage, FormInfo, FormInput
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


def _form_page(action: str, method: str = "GET", names=("q",)) -> CrawledPage:
    return CrawledPage(
        url="https://example.com/",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="<html></html>",
        forms=[FormInfo(action=action, method=method, inputs=[FormInput(name=n) for n in names])],
    )


def _reflect(escape: bool):
    def side_effect(request):
        vals = " ".join(request.url.params.values())
        return respx.MockResponse(200, text=f"<p>{html.escape(vals) if escape else vals}</p>")
    return side_effect


@respx.mock
def test_xss_reflected_form_field(sample_target: Target, sample_config: ScanConfig) -> None:
    respx.get("https://example.com/buscar").mock(side_effect=_reflect(escape=False))
    page = _form_page("https://example.com/buscar", names=("q", "", "q", "lang"))

    with SafeHttpClient(sample_target, sample_config) as client:
        findings = XssModule().run(sample_target, client, [page], sample_config)

    # q y lang se prueban una vez cada uno; el campo sin nombre y el duplicado se omiten
    assert sorted(f.id for f in findings) == ["WSA-XSS-002", "WSA-XSS-002"]
    assert {f.url for f in findings} == {"https://example.com/buscar"}


@respx.mock
def test_xss_escaped_output_is_not_reported(sample_target: Target, sample_config: ScanConfig) -> None:
    respx.get("https://example.com/buscar").mock(side_effect=_reflect(escape=True))
    page = _form_page("https://example.com/buscar")
    page.url = "https://example.com/buscar?q=1"

    with SafeHttpClient(sample_target, sample_config) as client:
        assert XssModule().run(sample_target, client, [page], sample_config) == []


def test_xss_skips_out_of_scope_and_post_forms(sample_target: Target, sample_config: ScanConfig) -> None:
    pages = [_form_page("https://evil.test/collect"), _form_page("https://example.com/x", method="POST")]
    client = MagicMock()

    findings = XssModule().run(sample_target, client, pages, sample_config)

    assert findings == []
    client.get.assert_not_called()  # nunca se envía tráfico fuera de alcance


@respx.mock
def test_xss_tests_each_query_param_once(sample_target: Target, sample_config: ScanConfig) -> None:
    route = respx.get("https://example.com/s").mock(return_value=respx.MockResponse(200, text="ok"))
    pages = [
        CrawledPage(url=f"https://example.com/s?q={i}", status_code=200, headers={}, body="")
        for i in range(3)
    ]
    with SafeHttpClient(sample_target, sample_config) as client:
        XssModule().run(sample_target, client, pages, sample_config)
    assert route.call_count == 1
