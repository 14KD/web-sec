"""Módulo activo: Auditoría de configuraciones inseguras de CORS (Cross-Origin Resource Sharing)."""

from typing import List
from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule

ATTACKER_ORIGIN = "https://evil-attacker.example"


class CorsModule(BaseModule):
    """Detecta políticas CORS permisivas, reflejo de orígenes arbitrarios y exposición con credenciales."""

    name = "cors"
    description = "Evalúa la cabecera Access-Control-Allow-Origin y combinaciones peligrosas con credenciales."
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

        # Priorizar endpoints tipo API o servicios y luego páginas generales
        api_keywords = ("/api", "/json", "/v1", "/v2", "/graphql", "/rest", "/user", "/auth")
        api_urls = [p.url for p in crawled_pages if any(k in p.url.lower() for k in api_keywords)]
        other_urls = [p.url for p in crawled_pages if p.url not in api_urls]

        sample_urls = [target.url] + api_urls + other_urls
        sample_urls = list(dict.fromkeys(sample_urls))[:15]

        for url in sample_urls:
            if url in tested_urls:
                continue
            tested_urls.add(url)

            # Probar con origen arbitrario
            resp_attacker = client.get(url, headers={"Origin": ATTACKER_ORIGIN})
            if resp_attacker:
                headers = {k.lower(): v for k, v in resp_attacker.headers.items()}
                acao = headers.get("access-control-allow-origin", "")
                acac = headers.get("access-control-allow-credentials", "").lower()

                # Caso 1: Reflejo de origen arbitrario con credenciales habilitadas (Crítico)
                if acao == ATTACKER_ORIGIN and acac == "true":
                    findings.append(
                        Finding(
                            id="WSA-CORS-001",
                            title="Configuración Crítica de CORS: Reflejo de Origen Arbitrario con Credenciales",
                            module=self.name,
                            severity=Severity.CRITICAL,
                            description=(
                                f"El servidor confía ciegamente en el encabezado Origin ('{ATTACKER_ORIGIN}') y permite "
                                "el intercambio de credenciales autenticadas (`Access-Control-Allow-Credentials: true`)."
                            ),
                            evidence=f"Respuesta incluye:\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                            impact="Un sitio malicioso de terceros puede leer datos privados de usuarios autenticados mediante peticiones asíncronas.",
                            recommendation="Validar el origen contra una lista blanca estricta de dominios autorizados.",
                            reference="https://portswigger.net/web-security/cors",
                            url=url,
                        )
                    )
                # Caso 2: Reflejo de origen arbitrario sin credenciales
                elif acao == ATTACKER_ORIGIN:
                    findings.append(
                        Finding(
                            id="WSA-CORS-002",
                            title="CORS Permite Origen Arbitrario",
                            module=self.name,
                            severity=Severity.LOW,
                            description=f"La aplicación web refleja cualquier origen arbitrario en Access-Control-Allow-Origin.",
                            evidence=f"Access-Control-Allow-Origin: {acao}",
                            impact="Permite a scripts de cualquier sitio web leer las respuestas de este endpoint.",
                            recommendation="Restringir el encabezado a orígenes legítimos y confiables.",
                            reference="https://developer.mozilla.org/es/docs/Web/HTTP/CORS",
                            url=url,
                        )
                    )
                # Caso 3: Wildcard (*) con credenciales
                elif acao == "*" and acac == "true":
                    findings.append(
                        Finding(
                            id="WSA-CORS-003",
                            title="Configuración Inválida de CORS: Wildcard (*) con Credenciales",
                            module=self.name,
                            severity=Severity.MEDIUM,
                            description="La configuración CORS intenta usar wildcard '*' conjuntamente con credenciales.",
                            evidence="Access-Control-Allow-Origin: * y Access-Control-Allow-Credentials: true",
                            impact="Comportamiento inconsistente y error de política según especificación W3C.",
                            recommendation="Nunca usar comodín '*' si se requiere intercambio autenticado.",
                            reference="https://developer.mozilla.org/es/docs/Web/HTTP/CORS",
                            url=url,
                        )
                    )

            # Probar con origen 'null'
            resp_null = client.get(url, headers={"Origin": "null"})
            if resp_null:
                headers = {k.lower(): v for k, v in resp_null.headers.items()}
                acao_null = headers.get("access-control-allow-origin", "")
                acac_null = headers.get("access-control-allow-credentials", "").lower()
                if acao_null.lower() == "null" and acac_null == "true":
                    findings.append(
                        Finding(
                            id="WSA-CORS-004",
                            title="CORS Permite Origen 'null' con Credenciales",
                            module=self.name,
                            severity=Severity.HIGH,
                            description="La aplicación permite el origen especial 'null' con credenciales habilitadas.",
                            evidence="Access-Control-Allow-Origin: null con Access-Control-Allow-Credentials: true",
                            impact="Permite ataques desde iframes sandboxed locales o data URIs maliciosas.",
                            recommendation="Eliminar 'null' de los orígenes autorizados en CORS.",
                            reference="https://portswigger.net/web-security/cors",
                            url=url,
                        )
                    )

        return findings
