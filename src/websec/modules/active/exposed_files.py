"""Módulo activo: Detección no destructiva de archivos y rutas sensibles expuestas."""

import json
from pathlib import Path
from typing import Any, Dict, List

from websec.config import DATA_DIR, ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule


class ExposedFilesModule(BaseModule):
    """Comprueba de forma no destructiva la existencia de archivos confidenciales expuestos."""

    name = "exposed_files"
    description = "Busca archivos críticos expuestos (.git, .env, backups, admin, robots.txt, security.txt)."
    category = "active"

    def __init__(self) -> None:
        self.sensitive_paths = self._load_paths()

    def _load_paths(self) -> List[Dict[str, Any]]:
        path_file = DATA_DIR / "sensitive_paths.json"
        if path_file.exists():
            try:
                return json.loads(path_file.read_text(encoding="utf-8"))
            except Exception:
                return []
        return []

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []

        sev_map = {
            "Crítica": Severity.CRITICAL,
            "Alta": Severity.HIGH,
            "Media": Severity.MEDIUM,
            "Baja": Severity.LOW,
            "Informativa": Severity.INFO,
        }

        for item in self.sensitive_paths:
            path = item["path"]
            url = f"{target.base_url.rstrip('/')}{path}"

            # Petición segura con limitación de rate limit
            resp = client.get(url)
            if resp and resp.status_code == 200:
                # Comprobar si requiere validación de contenido para evitar falsos positivos de páginas 404 personalizadas
                match_content = item.get("match_content")
                is_valid = True
                if match_content and match_content not in resp.text:
                    is_valid = False

                if is_valid:
                    sev = sev_map.get(item.get("severity", "Media"), Severity.MEDIUM)
                    findings.append(
                        Finding(
                            id=f"WSA-EXP-{path.replace('/', '_').replace('.', '_').strip('_').upper()}",
                            title=item["name"],
                            module=self.name,
                            severity=sev,
                            description=f"La ruta sensible '{path}' es accesible públicamente sin autenticación.",
                            evidence=f"Respuesta HTTP 200 en {url}. (Prueba no destructiva realizada sin descargar contenido confidencial).",
                            impact=item.get("impact", "Posible exposición de credenciales o arquitectura interna."),
                            recommendation="Restringir el acceso en la configuración del servidor web o mover los archivos fuera de la raíz pública.",
                            reference="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
                            url=url,
                        )
                    )

        return findings
