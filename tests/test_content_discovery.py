"""Pruebas de descubrimiento de contenido con wordlist."""

import respx
from websec.config import ScanConfig
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.active.content_discovery import ContentDiscoveryModule


@respx.mock
def test_content_discovery_phpinfo_and_admin(sample_target: Target, sample_config: ScanConfig) -> None:
    respx.get("https://example.com/phpinfo").respond(status_code=200, text="PHP Version 7.4.3")
    respx.get("https://example.com/dashboard").respond(status_code=200, text="Dashboard HTML")
    # Otras rutas retornan 404
    respx.get(url__regex=r"https://example\.com/(?!phpinfo|dashboard).*").respond(status_code=404)

    with SafeHttpClient(sample_target, sample_config) as client:
        module = ContentDiscoveryModule()
        findings = module.run(sample_target, client, [], sample_config)

        finding_ids = {f.id for f in findings}
        assert "WSA-DISC-PHPINFO" in finding_ids
        assert "WSA-DISC-001" in finding_ids
