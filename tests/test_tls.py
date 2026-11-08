"""Pruebas del módulo pasivo de TLS y certificados con mocks."""

import pytest
import respx
from unittest.mock import patch
from websec.config import ScanConfig
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.passive.tls import TlsModule


@respx.mock
def test_tls_missing_redirect(sample_target: Target, sample_config: ScanConfig) -> None:
    respx.get("http://example.com").respond(status_code=200, text="Plain HTTP Content")

    with SafeHttpClient(sample_target, sample_config) as client:
        module = TlsModule()
        with patch.object(module, "_get_certificate_info", return_value={"notAfter": "May 01 12:00:00 2030 GMT"}):
            findings = module.run(sample_target, client, [], sample_config)

            assert any(f.id == "WSA-TLS-001" for f in findings)


def test_tls_expired_certificate(sample_target: Target, sample_config: ScanConfig) -> None:
    with SafeHttpClient(sample_target, sample_config) as client:
        module = TlsModule()
        # Certificado expirado en el pasado
        fake_cert = {"notAfter": "Jan 01 12:00:00 2020 GMT"}
        with patch.object(module, "_get_certificate_info", return_value=fake_cert):
            findings = module.run(sample_target, client, [], sample_config)
            assert any(f.id == "WSA-TLS-002" for f in findings)
