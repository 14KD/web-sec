"""Módulo activo: Auditoría de protección contra CSRF (Cross-Site Request Forgery) en formularios."""

from typing import List
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule

CSRF_KEYWORDS = {"csrf", "xsrf", "token", "authenticity_token", "_csrf", "nonce", "state"}


class CsrfModule(BaseModule):
    """Identifica formularios que alteran estado (POST/PUT/DELETE) desprovistos de tokens anti-CSRF."""

    name = "csrf"
    description = "Comprueba la presencia de tokens anti-CSRF en formularios que realizan acciones sensibles."
    category = "active"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []
        analyzed_forms = set()

        for page in crawled_pages:
            for form in page.forms:
                if form.method in ("POST", "PUT", "DELETE"):
                    form_key = (page.url, form.action)
                    if form_key in analyzed_forms:
                        continue
                    analyzed_forms.add(form_key)

                    # Verificar si cuenta con token anti-CSRF
                    has_token = form.has_csrf
                    if not has_token:
                        # Re-verificar entre los nombres de campos
                        for inp in form.inputs:
                            if any(k in inp.name.lower() for k in CSRF_KEYWORDS):
                                has_token = True
                                break

                    if not has_token:
                        input_names = [i.name for i in form.inputs if i.name]
                        findings.append(
                            Finding(
                                id="WSA-CSRF-001",
                                title=f"Formulario Sensible sin Token Anti-CSRF ({form.method})",
                                module=self.name,
                                severity=Severity.MEDIUM,
                                description=(
                                    f"Se encontró un formulario {form.method} en '{page.url}' con destino a '{form.action}' "
                                    "que no incluye ningún campo oculto con token de sincronización anti-CSRF."
                                ),
                                evidence=f"Campos del formulario detectados: {input_names}. Sin token CSRF evidente.",
                                impact="Un atacante puede inducir a un usuario autenticado a enviar el formulario de manera involuntaria desde un sitio web malicioso.",
                                recommendation="Implementar tokens anti-CSRF criptográficos impredecibles (ej. Synchronizer Token Pattern o cookies SameSite=Strict).",
                                reference="https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                                url=page.url,
                            )
                        )

        return findings
