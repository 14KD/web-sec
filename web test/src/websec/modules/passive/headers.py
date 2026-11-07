"""Módulo pasivo: Auditoría de cabeceras HTTP de seguridad y fuga de información."""

from typing import List
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule


class HeadersModule(BaseModule):
    """Analiza cabeceras de seguridad y detecta divulgación de tecnologías del servidor."""

    name = "headers"
    description = "Audita cabeceras HTTP de seguridad (CSP, HSTS, X-Frame-Options...) y fuga de versiones."
    category = "passive"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []
        if not crawled_pages:
            return findings

        # Evaluar la página principal y las respuestas obtenidas
        main_page = crawled_pages[0]
        headers = {k.lower(): v for k, v in main_page.headers.items()}
        url = main_page.url

        # 1. Content-Security-Policy (CSP)
        if "content-security-policy" not in headers:
            findings.append(
                Finding(
                    id="WSA-HDR-001",
                    title="Cabecera Content-Security-Policy Ausente",
                    module=self.name,
                    severity=Severity.HIGH,
                    description="El sitio web no define una política de seguridad de contenido (CSP), lo que expone a los usuarios a ataques de inyección de código y XSS.",
                    evidence=f"Respuesta de {url} carece de cabecera 'Content-Security-Policy'.",
                    impact="Permite la carga e inyección no autorizada de scripts, marcos y estilos maliciosos en el navegador del usuario.",
                    recommendation="Implementar una cabecera CSP restrictiva (ej. `default-src 'self'; script-src 'self'`).",
                    reference="https://developer.mozilla.org/es/docs/Web/HTTP/CSP",
                    url=url,
                )
            )
        else:
            csp_val = headers["content-security-policy"]
            if "'unsafe-inline'" in csp_val or "'unsafe-eval'" in csp_val:
                findings.append(
                    Finding(
                        id="WSA-HDR-002",
                        title="Política CSP con Directivas Inseguras (unsafe-inline / unsafe-eval)",
                        module=self.name,
                        severity=Severity.MEDIUM,
                        description="La política CSP contiene 'unsafe-inline' o 'unsafe-eval', debilitando significativamente la protección contra Cross-Site Scripting.",
                        evidence=f"Content-Security-Policy: {csp_val}",
                        impact="Un atacante puede ejecutar scripts inline si logra inyectar código HTML en las páginas.",
                        recommendation="Eliminar 'unsafe-inline' y usar hashes criptográficos o nonces para scripts necesarios.",
                        reference="https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
                        url=url,
                    )
                )

        # 2. Strict-Transport-Security (HSTS)
        if target.scheme == "https":
            if "strict-transport-security" not in headers:
                findings.append(
                    Finding(
                        id="WSA-HDR-003",
                        title="Cabecera HSTS (Strict-Transport-Security) Ausente",
                        module=self.name,
                        severity=Severity.MEDIUM,
                        description="El sitio soporta HTTPS pero no fuerza la conexión cifrada a través de HSTS.",
                        evidence=f"Respuesta de {url} no incluye 'Strict-Transport-Security'.",
                        impact="Facilita ataques de degradación de cifrado (SSL Stripping) e intermediación de tráfico (MitM).",
                        recommendation="Configurar HSTS con directiva `max-age=31536000; includeSubDomains; preload`.",
                        reference="https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Strict-Transport-Security",
                        url=url,
                    )
                )

        # 3. X-Frame-Options
        if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
            findings.append(
                Finding(
                    id="WSA-HDR-004",
                    title="Cabecera X-Frame-Options Ausente (Riesgo de Clickjacking)",
                    module=self.name,
                    severity=Severity.MEDIUM,
                    description="No se restringe si la página puede ser incrustada en iframes o frames de otros dominios.",
                    evidence=f"Ausencia de 'X-Frame-Options' y de directiva CSP 'frame-ancestors'.",
                    impact="Permite que sitios web de terceros superpongan capas invisibles para inducir clics involuntarios (Clickjacking).",
                    recommendation="Agregar la cabecera `X-Frame-Options: DENY` o `SAMEORIGIN`, o configurar `frame-ancestors` en CSP.",
                    reference="https://owasp.org/www-community/attacks/Clickjacking",
                    url=url,
                )
            )

        # 4. X-Content-Type-Options
        x_content = headers.get("x-content-type-options", "").lower().strip()
        if x_content != "nosniff":
            findings.append(
                Finding(
                    id="WSA-HDR-005",
                    title="Cabecera X-Content-Type-Options no configurada como 'nosniff'",
                    module=self.name,
                    severity=Severity.LOW,
                    description="La cabecera no previene el rastreo e inferencia de tipos MIME (MIME-sniffing) por parte de los navegadores.",
                    evidence=f"X-Content-Type-Options actual: '{headers.get('x-content-type-options', 'Ausente')}'.",
                    impact="Permite que archivos con contenido ejecutable oculto sean interpretados como scripts por navegadores antiguos.",
                    recommendation="Añadir la cabecera `X-Content-Type-Options: nosniff` en todas las respuestas.",
                    reference="https://developer.mozilla.org/es/docs/Web/HTTP/Headers/X-Content-Type-Options",
                    url=url,
                )
            )

        # 5. Referrer-Policy
        if "referrer-policy" not in headers:
            findings.append(
                Finding(
                    id="WSA-HDR-006",
                    title="Cabecera Referrer-Policy Ausente",
                    module=self.name,
                    severity=Severity.LOW,
                    description="No se define el control de envío de la cabecera Referer al navegar hacia enlaces externos.",
                    evidence=f"Respuesta de {url} no especifica 'Referrer-Policy'.",
                    impact="Rutas internas sensibles o tokens incluidos en URLs pueden filtrarse en las peticiones a terceros.",
                    recommendation="Establecer `Referrer-Policy: strict-origin-when-cross-origin` o `no-referrer`.",
                    reference="https://developer.mozilla.org/es/docs/Web/HTTP/Headers/Referrer-Policy",
                    url=url,
                )
            )

        # 6. Permissions-Policy
        if "permissions-policy" not in headers:
            findings.append(
                Finding(
                    id="WSA-HDR-007",
                    title="Cabecera Permissions-Policy no definida",
                    module=self.name,
                    severity=Severity.INFO,
                    description="No se restringen explícitamente las APIs del navegador como geolocalización, cámara o micrófono.",
                    evidence=f"Cabecera 'Permissions-Policy' ausente en {url}.",
                    impact="El navegador no inhabilita proactivamente APIs de hardware en iframes o contextos delegados.",
                    recommendation="Configurar `Permissions-Policy: camera=(), microphone=(), geolocation=()` según requerimientos.",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    url=url,
                )
            )

        # 7. Divulgación de información de servidores (Server / X-Powered-By)
        if "server" in headers:
            server_val = headers["server"]
            # Si expone números de versión
            if any(char.isdigit() for char in server_val):
                findings.append(
                    Finding(
                        id="WSA-HDR-008",
                        title="Divulgación de Versión del Servidor Web (Server Header)",
                        module=self.name,
                        severity=Severity.LOW,
                        description="La cabecera 'Server' expone el nombre y la versión exacta del servidor web en uso.",
                        evidence=f"Server: {server_val}",
                        impact="Facilita el reconocimiento a atacantes para buscar CVEs específicos de esa versión.",
                        recommendation="Ocultar o anonimizar la versión en la configuración del servidor (ej. `ServerTokens Prod` en Apache o `server_tokens off;` en Nginx).",
                        reference="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
                        url=url,
                    )
                )

        if "x-powered-by" in headers:
            powered_val = headers["x-powered-by"]
            findings.append(
                Finding(
                    id="WSA-HDR-009",
                    title="Fuga de Información de Tecnología Backend (X-Powered-By)",
                    module=self.name,
                    severity=Severity.LOW,
                    description="La cabecera 'X-Powered-By' expone el framework o lenguaje backend utilizado.",
                    evidence=f"X-Powered-By: {powered_val}",
                    impact="Permite al atacante enfocar vectores de ataque dirigidos al stack tecnológico detectado.",
                    recommendation="Deshabilitar la cabecera (ej. `app.disable('x-powered-by')` en Express o `expose_php = Off` en php.ini).",
                    reference="https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
                    url=url,
                )
            )

        return findings
