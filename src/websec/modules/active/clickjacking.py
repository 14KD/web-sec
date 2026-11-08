"""Módulo activo: Auditoría de protección contra Clickjacking (Framing)."""

from typing import List
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule


class ClickjackingModule(BaseModule):
    """Comprueba si las páginas de la aplicación pueden incrustarse en marcos (iframes) externos."""

    name = "clickjacking"
    description = "Evalúa la vulnerabilidad de Clickjacking analizando X-Frame-Options y CSP frame-ancestors."
    category = "active"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []
        tested_urls = set()

        pages_to_check = crawled_pages if crawled_pages else []
        if not pages_to_check:
            resp = client.get(target.url)
            if resp:
                pages_to_check.append(
                    CrawledPage(
                        url=target.url,
                        status_code=resp.status_code,
                        headers=dict(resp.headers),
                        body=resp.text,
                    )
                )

        for page in pages_to_check:
            if page.url in tested_urls:
                continue
            tested_urls.add(page.url)

            headers = {k.lower(): v for k, v in page.headers.items()}
            xfo = headers.get("x-frame-options", "").upper().strip()
            csp = headers.get("content-security-policy", "").lower()

            has_xfo = xfo in ("DENY", "SAMEORIGIN")
            has_csp_frame = "frame-ancestors" in csp

            # Si no cuenta con ninguna de las dos defensas
            if not has_xfo and not has_csp_frame:
                has_forms = len(page.forms) > 0
                severity = Severity.MEDIUM if has_forms else Severity.LOW

                findings.append(
                    Finding(
                        id="WSA-CLK-001",
                        title=f"Página Vulnerable a Clickjacking ({page.url})",
                        module=self.name,
                        severity=severity,
                        description=(
                            f"La página '{page.url}' no define ni 'X-Frame-Options' ni la directiva CSP 'frame-ancestors', "
                            "permitiendo su carga dentro de un elemento <iframe> por cualquier sitio externo."
                        ),
                        evidence=f"Respuesta HTTP sin protecciones de enmarcado (X-Frame-Options / frame-ancestors). Formularios interactivos presentes: {has_forms}",
                        impact="Un atacante puede engañar a usuarios autenticados para que hagan clic en botones o formulaciones sensibles mediante capas transparentes.",
                        recommendation="Configurar `Content-Security-Policy: frame-ancestors 'self'` o `X-Frame-Options: SAMEORIGIN`.",
                        reference="https://owasp.org/www-community/attacks/Clickjacking",
                        url=page.url,
                    )
                )

        return findings
