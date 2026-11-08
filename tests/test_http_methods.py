"""Pruebas de métodos HTTP habilitados vía OPTIONS."""

import respx
from websec.config import ScanConfig
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.active.http_methods import HttpMethodsModule


@respx.mock
def test_http_methods_trace_and_put_enabled(sample_target: Target, sample_config: ScanConfig) -> None:
    respx.options("https://example.com").respond(
        status_code=200,
        headers={"Allow": "GET, POST, OPTIONS, TRACE, PUT"},
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = HttpMethodsModule()
        findings = module.run(sample_target, client, [], sample_config)

        finding_ids = {f.id for f in findings}
        assert "WSA-METH-001" in finding_ids  # TRACE enabled
        assert "WSA-METH-002" in finding_ids  # PUT enabled
