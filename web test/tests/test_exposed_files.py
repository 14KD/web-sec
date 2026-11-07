"""Pruebas de archivos sensibles expuestos con mocks."""

import respx
from websec.config import ScanConfig
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target
from websec.modules.active.exposed_files import ExposedFilesModule


@respx.mock
def test_exposed_git_and_env_files(sample_target: Target, sample_config: ScanConfig) -> None:
    respx.get("https://example.com/.git/HEAD").respond(status_code=200, text="ref: refs/heads/main\n")
    respx.get("https://example.com/.env").respond(status_code=200, text="DB_PASSWORD=secret123\n")
    respx.get("https://example.com/.well-known/security.txt").respond(status_code=404)
    respx.get("https://example.com/robots.txt").respond(status_code=404)
    respx.get("https://example.com/sitemap.xml").respond(status_code=404)
    respx.get("https://example.com/admin").respond(status_code=404)
    respx.get("https://example.com/backup.zip").respond(status_code=404)

    with SafeHttpClient(sample_target, sample_config) as client:
        module = ExposedFilesModule()
        findings = module.run(sample_target, client, [], sample_config)

        finding_ids = {f.id for f in findings}
        assert any("GIT_HEAD" in fid for fid in finding_ids)
        assert any("ENV" in fid for fid in finding_ids)
