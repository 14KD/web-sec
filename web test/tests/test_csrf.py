"""Pruebas de detección de formularios sin protección anti-CSRF."""

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage, FormInfo, FormInput
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.active.csrf import CsrfModule


def test_csrf_vulnerable_form(sample_target: Target, sample_config: ScanConfig) -> None:
    page = CrawledPage(
        url="https://example.com/settings",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="<html>Settings</html>",
        forms=[
            FormInfo(
                action="/change-email",
                method="POST",
                inputs=[FormInput(name="email", input_type="email", value="test@example.com")],
                has_csrf=False,
            )
        ],
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = CsrfModule()
        findings = module.run(sample_target, client, [page], sample_config)

        assert len(findings) == 1
        assert findings[0].id == "WSA-CSRF-001"


def test_csrf_protected_form(sample_target: Target, sample_config: ScanConfig) -> None:
    page = CrawledPage(
        url="https://example.com/settings",
        status_code=200,
        headers={"Content-Type": "text/html"},
        body="<html>Settings</html>",
        forms=[
            FormInfo(
                action="/change-email",
                method="POST",
                inputs=[
                    FormInput(name="email", input_type="email", value="test@example.com"),
                    FormInput(name="csrf_token", input_type="hidden", value="secure_token_123"),
                ],
                has_csrf=True,
            )
        ],
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = CsrfModule()
        findings = module.run(sample_target, client, [page], sample_config)

        assert len(findings) == 0
