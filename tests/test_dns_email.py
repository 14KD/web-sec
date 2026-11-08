"""Pruebas del módulo DNS y seguridad de correo electrónico con mocks."""

from unittest.mock import patch
from websec.config import ScanConfig
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.passive.dns_email import DnsEmailModule


def test_dns_email_missing_records(sample_target: Target, sample_config: ScanConfig) -> None:
    with SafeHttpClient(sample_target, sample_config) as client:
        module = DnsEmailModule()
        with patch.object(module, "_get_txt_record", return_value=None), \
             patch.object(module, "_check_caa_record", return_value=False):
            findings = module.run(sample_target, client, [], sample_config)

            finding_ids = {f.id for f in findings}
            assert "WSA-DNS-001" in finding_ids  # Missing SPF
            assert "WSA-DNS-003" in finding_ids  # Missing DMARC
            assert "WSA-DNS-005" in finding_ids  # Missing CAA


def test_dns_email_permissive_spf_and_weak_dmarc(sample_target: Target, sample_config: ScanConfig) -> None:
    def fake_txt(name: str, prefix: str):
        if "dmarc" in name:
            return "v=DMARC1; p=none; rua=mailto:test@example.com"
        return "v=spf1 include:_spf.google.com +all"

    with SafeHttpClient(sample_target, sample_config) as client:
        module = DnsEmailModule()
        with patch.object(module, "_get_txt_record", side_effect=fake_txt), \
             patch.object(module, "_check_caa_record", return_value=True):
            findings = module.run(sample_target, client, [], sample_config)

            finding_ids = {f.id for f in findings}
            assert "WSA-DNS-002" in finding_ids  # Permissive SPF (+all)
            assert "WSA-DNS-004" in finding_ids  # Weak DMARC (p=none)
