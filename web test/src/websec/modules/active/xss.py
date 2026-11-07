"""Módulo activo: Detección no destructiva de XSS reflejado mediante marcadores inocuos."""

from typing import List
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
import uuid

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule


class XssModule(BaseModule):
    """Evalúa el reflejo no sanitizado de parámetros de entrada mediante canarios inocuos."""

    name = "xss"
    description = "Prueba de XSS reflejado con marcadores canarios inocuos (sin código ejecutable)."
    category = "active"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []
        tested_params = set()

        for page in crawled_pages:
            parsed = urlparse(page.url)
            query_params = parse_qs(parsed.query)

            # 1. Probar parámetros en query strings GET
            for param_name in query_params.keys():
                param_key = (page.url.split("?")[0], param_name)
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)

                # Generar marcador canario único e inocuo
                canary_id = uuid.uuid4().hex[:8]
                canary = f"wsa_xss_{canary_id}"
                probe_payload = f'wsa">{canary}'

                # Reemplazar parámetro con payload
                new_params = dict(query_params)
                new_params[param_name] = [probe_payload]
                new_query = urlencode(new_params, doseq=True)
                probe_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                ))

                resp = client.get(probe_url)
                if resp and resp.status_code == 200:
                    # Verificar si el payload se refleja sin escapar en el cuerpo HTML
                    if probe_payload in resp.text:
                        findings.append(
                            Finding(
                                id="WSA-XSS-001",
                                title=f"Posible XSS Reflejado en Parámetro '{param_name}'",
                                module=self.name,
                                severity=Severity.HIGH,
                                description=f"El parámetro '{param_name}' refleja caracteres especiales HTML sin sanitización en la respuesta.",
                                evidence=f"Payload inocuo '{probe_payload}' reflejado textualmente en respuesta de {probe_url}",
                                impact="Permite a un atacante inyectar scripts en el navegador de usuarios mediante enlaces maliciosos.",
                                recommendation="Codificar la salida en HTML (`html.escape` o contextual escaping) y usar CSP estricto.",
                                reference="https://owasp.org/www-community/attacks/xss/",
                                url=probe_url,
                            )
                        )

            # 2. Probar formularios GET con parámetros
            for form in page.forms:
                if form.method.upper() == "GET" and form.inputs:
                    form_action = form.action or page.url
                    if not target.in_scope(form_action, config.allow_subdomains):
                        continue
                    for inp in form.inputs:
                        if not inp.name:
                            continue
                        form_key = (form_action, inp.name)
                        if form_key in tested_params:
                            continue
                        tested_params.add(form_key)

                        canary_id = uuid.uuid4().hex[:8]
                        canary = f"wsa_form_{canary_id}"
                        probe_payload = f'wsa">{canary}'

                        form_data = {i.name: (probe_payload if i.name == inp.name else "test") for i in form.inputs if i.name}
                        resp = client.get(form_action, params=form_data)
                        if resp and resp.status_code == 200 and probe_payload in resp.text:
                            findings.append(
                                Finding(
                                    id="WSA-XSS-002",
                                    title=f"XSS Reflejado en Campo de Formulario '{inp.name}'",
                                    module=self.name,
                                    severity=Severity.HIGH,
                                    description=f"El campo '{inp.name}' del formulario en {form_action} refleja valores sin codificación HTML.",
                                    evidence=f"Reflejo del marcador '{canary}' en respuesta de formulario.",
                                    impact="Ejecución no autorizada de código de script en la sesión de los usuarios que envíen el formulario.",
                                    recommendation="Sanitizar y escapar la salida de todos los campos de formulario renderizados.",
                                    reference="https://owasp.org/www-community/attacks/xss/",
                                    url=form_action,
                                )
                            )

        return findings
