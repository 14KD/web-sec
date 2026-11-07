"""Pruebas drásticas de integración End-to-End (E2E) contra el Laboratorio Vulnerable real.

Levanta un servidor local en vivo con `lab/app.py` y ejecuta el motor completo
`SecurityScanner` validando que detecta las vulnerabilidades deliberadas del laboratorio.
"""

import socket
import sys
from pathlib import Path
import threading
import time
from typing import Generator
import pytest
import httpx

# Asegurar que el directorio raíz de web test esté en sys.path para importar lab
root_dir = Path(__file__).resolve().parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from lab.app import app as flask_lab_app
from websec.config import ScanConfig
from websec.core.scanner import SecurityScanner
from websec.modules import ALL_MODULES
from websec.reports.vulnerabilities_report import VulnerabilitiesReport


def get_free_port() -> int:
    """Obtiene un puerto TCP libre efímero en localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_vulnerable_lab() -> Generator[str, None, None]:
    """Fixture que levanta el laboratorio Flask real en un hilo daemon efímero."""
    port = get_free_port()
    base_url = f"http://127.0.0.1:{port}"

    from werkzeug.serving import make_server
    server = make_server("127.0.0.1", port, flask_lab_app, threaded=True)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # Esperar hasta que responda
    for _ in range(50):
        try:
            r = httpx.get(base_url, timeout=0.5)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.05)

    yield base_url

    server.shutdown()


def test_e2e_full_scan_against_live_lab(live_vulnerable_lab: str, tmp_path) -> None:
    """Ejecuta una auditoría completa real sobre el laboratorio y valida los hallazgos."""
    config = ScanConfig(
        target_url=live_vulnerable_lab,
        has_permission=True,
        rate_limit=50.0,
        timeout=3.0,
        crawl_depth=2,
        max_pages=20,
        output_dir=tmp_path,
    )

    scanner = SecurityScanner(config)
    for mod_cls in ALL_MODULES:
        scanner.register_module(mod_cls())

    result = scanner.run()

    # 1. El escaneo debe haber encontrado páginas en el crawl
    assert len(result.crawled_urls) >= 5
    assert result.stats.requests_made > 10

    # 2. Debe identificar vulnerabilidades críticas y altas
    findings_ids = {f.id for f in result.findings}
    findings_modules = {f.module for f in result.findings}

    # Verificar que detectó las vulnerabilidades del laboratorio:
    # - XSS reflejado
    assert "xss" in findings_modules or any("XSS" in f.id for f in result.findings)
    # - Inyección SQL heurística
    assert "sqli" in findings_modules or any("SQL" in f.id for f in result.findings)
    # - CORS inseguro
    assert "cors" in findings_modules or any("CORS" in f.id for f in result.findings)
    # - Formulario sin CSRF
    assert "csrf" in findings_modules or any("CSRF" in f.id for f in result.findings)
    # - Cookies inseguras
    assert "cookies" in findings_modules or any("COOKIE" in f.id for f in result.findings)
    # - Páginas de error con stack trace
    assert "error_pages" in findings_modules or any("ERR" in f.id for f in result.findings)

    # 3. La puntuación global debe reflejar el estado vulnerable
    assert result.score is not None
    assert result.score.score < 70  # Postura vulnerable (C, D o F)
    assert result.score.grade in ("C", "D", "F")

    # 4. Generación de artefactos de reporte
    vuln_json = tmp_path / "vulnerabilities.json"
    vuln_md = tmp_path / "VULNERABILITIES.md"
    VulnerabilitiesReport.generate_json(result, vuln_json)
    VulnerabilitiesReport.generate_markdown(result, vuln_md)

    assert vuln_json.exists()
    assert vuln_md.exists()
    assert vuln_md.stat().st_size > 500
