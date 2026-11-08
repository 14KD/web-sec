"""Módulo pasivo: Auditoría de flags de seguridad en Cookies (Secure, HttpOnly, SameSite)."""

from http.cookies import SimpleCookie
from typing import List, Set
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule

SESSION_KEYWORDS = {"session", "sess", "token", "jwt", "auth", "phpsessid", "jsessionid", "connect.sid"}


class CookiesModule(BaseModule):
    """Verifica la presencia y correcta configuración de flags de seguridad en cookies HTTP."""

    name = "cookies"
    description = "Inspecciona cookies de sesión y almacenamiento para flags Secure, HttpOnly y SameSite."
    category = "passive"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []
        analyzed_cookies: Set[str] = set()

        for page in crawled_pages:
            headers = {k.lower(): v for k, v in page.headers.items()}
            set_cookie_raw = headers.get("set-cookie")
            if not set_cookie_raw:
                continue

            cookie_parser = SimpleCookie()
            try:
                cookie_parser.load(set_cookie_raw)
            except Exception:
                continue

            for cookie_name, morsel in cookie_parser.items():
                if cookie_name in analyzed_cookies:
                    continue
                analyzed_cookies.add(cookie_name)

                is_session = any(k in cookie_name.lower() for k in SESSION_KEYWORDS)

                # 1. Flag Secure
                if target.scheme == "https" and not morsel.get("secure"):
                    severity = Severity.HIGH if is_session else Severity.MEDIUM
                    findings.append(
                        Finding(
                            id="WSA-CK-001",
                            title=f"Cookie '{cookie_name}' sin Flag 'Secure'",
                            module=self.name,
                            severity=severity,
                            description=f"La cookie '{cookie_name}' no incluye el atributo 'Secure', lo que permite su transmisión en texto claro a través de HTTP.",
                            evidence=f"Set-Cookie: {morsel.OutputString()}",
                            impact="La cookie puede ser interceptada si el usuario realiza alguna petición HTTP accidental en la misma red.",
                            recommendation=f"Agregar el atributo `Secure` a la cookie '{cookie_name}' al generarla en el servidor.",
                            reference="https://developer.mozilla.org/es/docs/Web/HTTP/Cookies#cookies_seguras",
                            url=page.url,
                        )
                    )

                # 2. Flag HttpOnly
                if not morsel.get("httponly"):
                    severity = Severity.HIGH if is_session else Severity.LOW
                    findings.append(
                        Finding(
                            id="WSA-CK-002",
                            title=f"Cookie '{cookie_name}' sin Flag 'HttpOnly'",
                            module=self.name,
                            severity=severity,
                            description=f"La cookie '{cookie_name}' es accesible mediante scripts del lado del cliente (`document.cookie`).",
                            evidence=f"Set-Cookie: {morsel.OutputString()}",
                            impact="En caso de una vulnerabilidad de XSS, un atacante puede robar inmediatamente esta cookie.",
                            recommendation=f"Configurar el atributo `HttpOnly` para la cookie '{cookie_name}'.",
                            reference="https://owasp.org/www-community/HttpOnly",
                            url=page.url,
                        )
                    )

                # 3. Atributo SameSite
                samesite = morsel.get("samesite", "").lower()
                if not samesite or samesite == "none":
                    findings.append(
                        Finding(
                            id="WSA-CK-003",
                            title=f"Cookie '{cookie_name}' sin Atributo 'SameSite' Adecuado",
                            module=self.name,
                            severity=Severity.MEDIUM if is_session else Severity.LOW,
                            description=f"La cookie '{cookie_name}' no restringe su envío en peticiones de origen cruzado (SameSite Ausente o None).",
                            evidence=f"SameSite actual: '{samesite or 'Ausente'}' en '{cookie_name}'.",
                            impact="Aumenta la exposición de la aplicación a ataques de falsificación de petición en sitios cruzados (CSRF).",
                            recommendation=f"Establecer `SameSite=Lax` o `SameSite=Strict` para la cookie '{cookie_name}'.",
                            reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                            url=page.url,
                        )
                    )

        return findings
