"""Módulo activo: Detección no destructiva de Open Redirect (Redirección abierta)."""

from typing import List
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule

REDIRECT_PARAM_NAMES = {
    "redirect", "redirect_to", "redirect_url", "url", "next", "return",
    "return_to", "return_url", "dest", "destination", "goto", "target", "out", "r",
}

CONTROL_URL = "https://example.com/wsa_open_redirect_control_check"


class OpenRedirectModule(BaseModule):
    """Detecta parámetros vulnerables a redirecciones no validadas hacia dominios externos."""

    name = "open_redirect"
    description = "Prueba de redirección abierta (Open Redirect) utilizando una URL de control segura."
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

        # Recopilar URLs candidatas con parámetros conocidos de redirección
        candidate_urls = [p.url for p in crawled_pages]
        # Agregar también las rutas base típicas de autenticación
        auth_paths = ["/login", "/auth/login", "/logout", "/redirect"]
        for p in auth_paths:
            candidate_urls.append(f"{target.base_url}{p}")

        for page_url in candidate_urls:
            parsed = urlparse(page_url)
            query_params = parse_qs(parsed.query)

            # Si ya tiene parámetros, o si es una ruta típica donde probar parámetros
            target_params = list(query_params.keys())
            if not target_params and parsed.path in auth_paths:
                target_params = ["redirect_to", "url", "next"]

            for param_name in target_params:
                if param_name.lower() not in REDIRECT_PARAM_NAMES and parsed.path not in auth_paths:
                    continue

                test_key = (parsed.path, param_name)
                if test_key in tested_urls:
                    continue
                tested_urls.add(test_key)

                new_params = dict(query_params)
                new_params[param_name] = [CONTROL_URL]
                new_query = urlencode(new_params, doseq=True)
                probe_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                ))

                resp = client.get(
                    probe_url,
                    follow_redirects=False,
                )
                if resp and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if location.startswith(CONTROL_URL) or location.startswith("https://example.com"):
                        findings.append(
                            Finding(
                                id="WSA-REDIR-001",
                                title=f"Vulnerabilidad de Open Redirect en Parámetro '{param_name}'",
                                module=self.name,
                                severity=Severity.MEDIUM,
                                description=(
                                    f"La aplicación redirige hacia una URL externa arbitraria controlada por el parámetro '{param_name}' "
                                    "sin validar el dominio de destino."
                                ),
                                evidence=f"Petición a {probe_url} retornó HTTP {resp.status_code} redirigiendo a: '{location}'",
                                impact="Permite a los atacantes orquestar campañas de phishing altamente convincentes usando el dominio legítimo.",
                                recommendation="Validar destinos de redirección contra una lista blanca estricta o admitir solo rutas relativas.",
                                reference="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                                url=probe_url,
                            )
                        )

        return findings
