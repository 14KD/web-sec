"""Módulo activo: Detección heurística no destructiva de SQL Injection por firmas de error."""

import re
from typing import List, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule

# Firmas de errores de bases de datos para detección heurística
SQL_ERROR_SIGNATURES: List[Tuple[str, str]] = [
    (r"You have an error in your SQL syntax", "MySQL / MariaDB"),
    (r"mysql_fetch_array\(\)|mysql_query\(\)", "MySQL PHP Driver"),
    (r"ERROR:\s+syntax error at or near", "PostgreSQL"),
    (r"org\.postgresql\.util\.PSQLException", "PostgreSQL JDBC"),
    (r"sqlite3\.OperationalError:|unrecognized token:.*syntax error", "SQLite"),
    (r"ORA-01756:|ORA-00933:", "Oracle DB"),
    (r"Unclosed quotation mark after the character string", "Microsoft SQL Server"),
    (r"Microsoft OLE DB Provider for SQL Server", "MSSQL OLE DB"),
    (r"SQLSTATE\[[0-9A-Z]+\]", "PDO / SQL General"),
]


class SqliModule(BaseModule):
    """Detecta indicios de inyección SQL enviando una comilla simple y analizando errores de sintaxis."""

    name = "sqli"
    description = "Heurística de SQL Injection basada en mensajes de error de sintaxis (sin extracción)."
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

            for param_name in query_params.keys():
                param_key = (page.url.split("?")[0], param_name)
                if param_key in tested_params:
                    continue
                tested_params.add(param_key)

                # Payload de prueba inocuo: comilla simple para romper sintaxis de consultas no parametrizadas
                probe_payload = "'"
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
                if resp:
                    for pattern, db_name in SQL_ERROR_SIGNATURES:
                        if re.search(pattern, resp.text, re.I):
                            findings.append(
                                Finding(
                                    id="WSA-SQLI-001",
                                    title=f"Posible SQL Injection Heurístico en Parámetro '{param_name}' ({db_name})",
                                    module=self.name,
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"El parámetro '{param_name}' provocó un mensaje de error de sintaxis de base de datos ({db_name}) "
                                        "al recibir una comilla simple."
                                    ),
                                    evidence=f"Firma de error detectada: '{pattern}' en respuesta de {probe_url}",
                                    impact="Un atacante podría leer o alterar la base de datos completa y comprometer la integridad del sistema.",
                                    recommendation="Utilizar consultas preparadas (Prepared Statements / ORMs) con paso de parámetros tipados.",
                                    reference="https://owasp.org/www-community/attacks/SQL_Injection",
                                    url=probe_url,
                                )
                            )
                            break

        return findings
