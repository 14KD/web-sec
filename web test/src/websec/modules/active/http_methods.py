"""Módulo activo: Auditoría de métodos HTTP habilitados vía OPTIONS."""

from typing import List, Set
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule


class HttpMethodsModule(BaseModule):
    """Comprueba los métodos HTTP soportados por el servidor web y detecta métodos inseguros (TRACE, PUT, DELETE)."""

    name = "http_methods"
    description = "Envía peticiones OPTIONS para detectar métodos HTTP potencialmente peligrosos habilitados."
    category = "active"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []

        resp = client.options(target.url)
        if not resp:
            return findings

        headers = {k.lower(): v for k, v in resp.headers.items()}
        allow_header = headers.get("allow", "") or headers.get("access-control-allow-methods", "")

        if not allow_header:
            return findings

        enabled_methods: Set[str] = {m.strip().upper() for m in allow_header.split(",") if m.strip()}

        # 1. Comprobación de método TRACE (Cross-Site Tracing - XST)
        if "TRACE" in enabled_methods:
            findings.append(
                Finding(
                    id="WSA-METH-001",
                    title="Método HTTP TRACE Habilitado (Riesgo de XST)",
                    module=self.name,
                    severity=Severity.HIGH,
                    description="El servidor web tiene habilitado el método HTTP TRACE, lo que permite ataques de Cross-Site Tracing (XST).",
                    evidence=f"Cabecera Allow: {allow_header}",
                    impact="Permite a un atacante que disponga de XSS extraer cookies marcadas con 'HttpOnly' leyendo el reflejo de la petición.",
                    recommendation="Deshabilitar el método TRACE en el servidor web (ej. `TraceEnable Off` en Apache).",
                    reference="https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                    url=target.url,
                )
            )

        # 2. Métodos PUT o DELETE habilitados públicamente
        risky_methods = {"PUT", "DELETE"} & enabled_methods
        if risky_methods:
            findings.append(
                Finding(
                    id="WSA-METH-002",
                    title=f"Métodos HTTP Peligrosos Habilitados ({', '.join(risky_methods)})",
                    module=self.name,
                    severity=Severity.MEDIUM,
                    description=f"El servidor reporta soporte para métodos de modificación y borrado de recursos ({', '.join(risky_methods)}).",
                    evidence=f"Métodos anunciados en cabecera Allow: {allow_header}",
                    impact="Si no existe autenticación estricta, usuarios anónimos podrían subir archivos maliciosos o eliminar recursos existentes.",
                    recommendation="Deshabilitar los métodos PUT y DELETE si no forman parte de una API REST protegida.",
                    reference="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
                    url=target.url,
                )
            )

        return findings
