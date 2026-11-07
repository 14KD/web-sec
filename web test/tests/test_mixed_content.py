"""Pruebas del módulo pasivo de contenido mixto."""

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.passive.mixed_content import MixedContentModule


def test_mixed_content_detection(sample_target: Target, sample_config: ScanConfig) -> None:
    html = """
    <html>
      <head>
        <script src="http://example.com/insecure.js"></script>
        <script src="https://cdn.example.org/lib.js"></script>
      </head>
      <body>
        <img src="http://example.com/logo.png">
      </body>
    </html>
    """
    page = CrawledPage(
        url="https://example.com",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=html,
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = MixedContentModule()
        findings = module.run(sample_target, client, [page], sample_config)

        finding_ids = {f.id for f in findings}
        assert "WSA-MC-001" in finding_ids  # Active mixed content (script)
        assert "WSA-MC-002" in finding_ids  # Passive mixed content (image)
        assert "WSA-MC-003" in finding_ids  # Missing SRI on 3rd party script
