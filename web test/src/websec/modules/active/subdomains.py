"""Módulo activo: Enumeración pasiva de subdominios vía Certificate Transparency (crt.sh) y DNS."""

import socket
from typing import List, Set
import httpx

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule


class SubdomainsModule(BaseModule):
    """Descubre subdominios del objetivo mediante registros de transparencia de certificados y verificación DNS."""

    name = "subdomains"
    description = "Enumeración pasiva de subdominios a través de crt.sh y resolución DNS no intrusiva."
    category = "active"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []
        domain = target.domain

        discovered_subs: Set[str] = set()

        # 1. Consulta a crt.sh (Certificate Transparency Logs)
        crt_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            # Petición externa a crt.sh usando httpx
            with httpx.Client(timeout=8.0) as crt_client:
                resp = crt_client.get(crt_url)
                if resp.status_code == 200:
                    records = resp.json()
                    for item in records:
                        name_value = item.get("name_value", "")
                        for sub in name_value.split("\n"):
                            sub = sub.strip().lower()
                            if sub.endswith(f".{domain}") and "*" not in sub:
                                discovered_subs.add(sub)
        except Exception:
            pass

        # 2. Verificación no intrusiva de resolución DNS de los subdominios encontrados
        active_subdomains: List[str] = []
        for sub in list(discovered_subs)[:20]:  # Limitar a máximo 20 para rapidez y control
            try:
                ip = socket.gethostbyname(sub)
                active_subdomains.append(f"{sub} -> {ip}")
            except Exception:
                continue

        if active_subdomains:
            findings.append(
                Finding(
                    id="WSA-SUB-001",
                    title=f"Subdominios Activos Descubiertos ({len(active_subdomains)})",
                    module=self.name,
                    severity=Severity.INFO,
                    description=f"Se identificaron subdominios activos asociados al dominio '{domain}' mediante registros de certificados SSL/TLS.",
                    evidence="Subdominios resolviendo:\n" + "\n".join(active_subdomains[:15]),
                    impact="Amplía la superficie de ataque del objetivo con posibles paneles de desarrollo, staging o APIs expuestas.",
                    recommendation="Verificar que todos los subdominios activos cuenten con las mismas políticas de seguridad y parches.",
                    reference="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage",
                    url=target.base_url,
                )
            )

        return findings
