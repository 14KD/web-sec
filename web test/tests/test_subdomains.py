"""Pruebas del módulo de subdominios vía Certificate Transparency con mocks."""

from unittest.mock import patch
import respx
from websec.config import ScanConfig
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.active.subdomains import SubdomainsModule


@respx.mock
def test_subdomains_discovery(sample_target: Target, sample_config: ScanConfig) -> None:
    crt_data = [
        {"name_value": "api.example.com"},
        {"name_value": "mail.example.com\nadmin.example.com"},
    ]
    respx.get("https://crt.sh/?q=%25.example.com&output=json").respond(json=crt_data)

    def fake_gethostbyname(hostname):
        if "api" in hostname:
            return "192.168.1.50"
        raise Exception("Name or service not known")

    with SafeHttpClient(sample_target, sample_config) as client:
        module = SubdomainsModule()
        with patch("socket.gethostbyname", side_effect=fake_gethostbyname):
            findings = module.run(sample_target, client, [], sample_config)

            assert len(findings) == 1
            assert findings[0].id == "WSA-SUB-001"
            assert "api.example.com" in findings[0].evidence
