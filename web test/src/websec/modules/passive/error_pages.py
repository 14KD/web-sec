"""Módulo pasivo: Detección de mensajes de error detallados, stack traces y divulgación de rutas."""

import re
from typing import List
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule

STACK_TRACE_PATTERNS = [
    (r"Traceback \(most recent call last\):", "Python Traceback"),
    (r"You're seeing this error because you have DEBUG = True", "Django Debug Mode"),
    (r"Werkzeug Debugger", "Flask/Werkzeug Debug Console"),
    (r"Fatal error:.*in\s+/.+on line \d+", "PHP Fatal Error"),
    (r"Whoops! There was an error\.", "Laravel Whoops / Ignition Error"),
    (r"Server Error in '/' Application\.", "ASP.NET Stack Trace"),
    (r"at\s+[\w\.\$]+\([\w\.]+\.java:\d+\)", "Java Stack Trace"),
    (r"at\s+[\w\.<>]+\s+\(node:internal/[\w/]+:\d+:\d+\)", "Node.js Stack Trace"),
]

PATH_DISCLOSURE_PATTERNS = [
    r"/[a-z0-9_\-\.]+/public_html/[a-z0-9_\-\./]+",
    r"/var/www/[a-z0-9_\-\./]+",
    r"[A-Z]:\\[a-zA-Z0-9_\-\\]+\.py",
    r"[A-Z]:\\inetpub\\wwwroot\\[a-zA-Z0-9_\-\\]+",
]


class ErrorPagesModule(BaseModule):
    """Detecta páginas de error 404/500 que exponen detalles internos del sistema o trazas de depuración."""

    name = "error_pages"
    description = "Comprueba el manejo de errores HTTP y detecta stack traces, modo debug o rutas internas."
    category = "passive"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Probar ruta inexistente para evaluar página 404
        probe_url = f"{target.base_url}/wsa_probe_nonexistent_{int(target.port or 80)}_err"
        resp_404 = client.get(probe_url)

        responses_to_check = []
        if resp_404:
            responses_to_check.append((probe_url, resp_404.status_code, resp_404.text))

        # Sumar páginas con errores obtenidas en el rastreo
        for page in crawled_pages:
            if page.status_code >= 400:
                responses_to_check.append((page.url, page.status_code, page.body))

        for check_url, status_code, body in responses_to_check:
            # Detección de trazas de depuración
            for pattern, trace_type in STACK_TRACE_PATTERNS:
                if re.search(pattern, body, re.I):
                    findings.append(
                        Finding(
                            id="WSA-ERR-001",
                            title=f"Fuga de Trazas de Depuración / Modo Debug ({trace_type})",
                            module=self.name,
                            severity=Severity.HIGH,
                            description=f"La respuesta HTTP con código {status_code} expone un stack trace de ejecución ({trace_type}).",
                            evidence=f"Patrón detectado en {check_url}: {trace_type}",
                            impact="Revela la arquitectura de archivos del servidor, líneas exactas de código y posibles secretos o consultas SQL.",
                            recommendation="Desactivar el modo depuración (DEBUG=False) en entornos de producción y configurar páginas de error genéricas.",
                            reference="https://owasp.org/www-community/Improper_Error_Handling",
                            url=check_url,
                        )
                    )
                    break

            # Detección de rutas internas de archivos
            for path_pat in PATH_DISCLOSURE_PATTERNS:
                match = re.search(path_pat, body)
                if match:
                    findings.append(
                        Finding(
                            id="WSA-ERR-002",
                            title="Divulgación de Rutas Internas del Sistema de Archivos",
                            module=self.name,
                            severity=Severity.LOW,
                            description="La respuesta de error incluye rutas absolutas del sistema de archivos local del servidor.",
                            evidence=f"Ruta detectada: {match.group(0)} en {check_url}",
                            impact="Ayuda al reconocimiento del entorno del servidor y estructura de directorios.",
                            recommendation="Personalizar las plantillas de error HTTP y suprimir mensajes del motor subyacente.",
                            reference="https://cwe.mitre.org/data/definitions/209.html",
                            url=check_url,
                        )
                    )
                    break

        return findings
