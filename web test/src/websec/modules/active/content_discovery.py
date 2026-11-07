"""Módulo activo: Descubrimiento ético y controlado de rutas no enlazadas (Content Discovery)."""

from pathlib import Path
from typing import List
from websec.config import DATA_DIR, ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule


class ContentDiscoveryModule(BaseModule):
    """Realiza un descubrimiento de directorios y rutas utilizando un diccionario pequeño y controlado."""

    name = "content_discovery"
    description = "Busca rutas y recursos no indexados utilizando una wordlist pequeña incluida."
    category = "active"

    def __init__(self) -> None:
        self.wordlist = self._load_wordlist()

    def _load_wordlist(self) -> List[str]:
        wl_path = DATA_DIR / "wordlist_small.txt"
        if wl_path.exists():
            try:
                lines = wl_path.read_text(encoding="utf-8").splitlines()
                return [line.strip() for line in lines if line.strip() and not line.startswith("#")]
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
        known_urls = {p.url for p in crawled_pages}

        discovered_routes: List[str] = []

        for word in self.wordlist:
            test_url = f"{target.base_url.rstrip('/')}/{word}"
            if test_url in known_urls:
                continue

            resp = client.get(test_url, follow_redirects=False)
            if resp and resp.status_code in (200, 301, 302, 403):
                # Descartar respuestas genéricas o errores
                if resp.status_code == 200 and "phpinfo" in word.lower():
                    findings.append(
                        Finding(
                            id="WSA-DISC-PHPINFO",
                            title="Ruta de phpinfo() Expuesta",
                            module=self.name,
                            severity=Severity.HIGH,
                            description=f"La ruta de diagnóstico '{test_url}' devolvió código HTTP 200.",
                            evidence=f"Respuesta HTTP {resp.status_code} en {test_url}",
                            impact="Divulga la configuración completa del entorno PHP, módulos instalados y variables de entorno.",
                            recommendation="Eliminar archivos phpinfo() de entornos en producción.",
                            reference="https://cwe.mitre.org/data/definitions/200.html",
                            url=test_url,
                        )
                    )
                elif resp.status_code in (200, 403):
                    discovered_routes.append(f"{test_url} (HTTP {resp.status_code})")

        if discovered_routes:
            findings.append(
                Finding(
                    id="WSA-DISC-001",
                    title="Rutas No Enlazadas Descubiertas",
                    module=self.name,
                    severity=Severity.INFO,
                    description=f"Se identificaron {len(discovered_routes)} rutas accesibles no enlazadas en el código HTML principal.",
                    evidence="Rutas descubiertas:\n" + "\n".join(discovered_routes[:10]),
                    impact="Permite cartografiar la superficie de exposición y ubicar endpoints administrativos o APIs no documentadas.",
                    recommendation="Revisar que los endpoints descubiertos cuenten con los controles de autenticación adecuados.",
                    reference="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                    url=target.base_url,
                )
            )

        return findings
