"""Pruebas del módulo pasivo de cookies."""

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.passive.cookies import CookiesModule


def test_insecure_session_cookie(sample_target: Target, sample_config: ScanConfig) -> None:
    page = CrawledPage(
        url="https://example.com/login",
        status_code=200,
        headers={"Set-Cookie": "session_id=abc123456; Path=/; Domain=example.com"},
        body="<html>Login</html>",
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = CookiesModule()
        findings = module.run(sample_target, client, [page], sample_config)

        finding_ids = {f.id for f in findings}
        assert "WSA-CK-001" in finding_ids  # Missing Secure
        assert "WSA-CK-002" in finding_ids  # Missing HttpOnly
        assert "WSA-CK-003" in finding_ids  # Missing SameSite


def test_secure_cookie(sample_target: Target, sample_config: ScanConfig) -> None:
    page = CrawledPage(
        url="https://example.com/login",
        status_code=200,
        headers={"Set-Cookie": "auth_token=secret; Secure; HttpOnly; SameSite=Strict; Path=/"},
        body="<html>Login</html>",
    )

    with SafeHttpClient(sample_target, sample_config) as client:
        module = CookiesModule()
        findings = module.run(sample_target, client, [page], sample_config)
        assert len(findings) == 0
