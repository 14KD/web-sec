"""Pruebas del módulo de análisis de páginas de error y stack traces."""

import respx
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.passive.error_pages import ErrorPagesModule


@respx.mock
def test_error_pages_stack_trace_leak(sample_target: Target, sample_config: ScanConfig) -> None:
    error_body = """
    <h1>Server Error</h1>
    <p>Traceback (most recent call last):</p>
    <pre>  File "/var/www/app/views.py", line 42, in get_user</pre>
    """
    respx.get("https://example.com/wsa_probe_nonexistent_80_err").respond(
        status_code=500,
        headers={"Content-Type": "text/html"},
        text=error_body,
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = ErrorPagesModule()
        findings = module.run(sample_target, client, [], sample_config)

        finding_ids = {f.id for f in findings}
        assert "WSA-ERR-001" in finding_ids  # Stack trace detected
        assert "WSA-ERR-002" in finding_ids  # Internal path detected (/var/www/...)
