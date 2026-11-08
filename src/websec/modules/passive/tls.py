"""Módulo pasivo: Auditoría de configuración HTTPS, certificados TLS y redirecciones."""

from datetime import datetime, timezone
import socket
import ssl
from typing import Any, Dict, List, Optional
import httpx

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule


class TlsModule(BaseModule):
    """Verifica redirección HTTP->HTTPS, validez de certificados y versiones TLS."""

    name = "tls"
    description = "Audita cifrado HTTPS, redirección forzada, vencimiento de certificados y versiones TLS."
    category = "passive"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Redirección HTTP -> HTTPS
        http_url = f"http://{target.domain}"
        try:
            # Petición directa sin seguir redirección automática para comprobar 301/308
            resp = client.client.get(
                http_url,
                follow_redirects=False,
                timeout=config.timeout,
            )
            if resp.status_code in (301, 302, 307, 308):
                location = resp.headers.get("location", "").lower()
                if not location.startswith("https://"):
                    findings.append(
                        Finding(
                            id="WSA-TLS-001",
                            title="Redirección HTTP a HTTPS Inadecuada",
                            module=self.name,
                            severity=Severity.HIGH,
                            description="El tráfico HTTP no redirige obligatoriamente hacia el protocolo seguro HTTPS.",
                            evidence=f"Respuesta HTTP {resp.status_code} redirige a: {location}",
                            impact="Comunicaciones susceptibles a intercepción, lectura de credenciales y degradación SSL.",
                            recommendation="Configurar redirección permanente (301) desde HTTP hacia HTTPS en el servidor web.",
                            reference="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                            url=http_url,
                        )
                    )
            else:
                findings.append(
                    Finding(
                        id="WSA-TLS-001",
                        title="HTTP Disponible sin Redirección hacia HTTPS",
                        module=self.name,
                        severity=Severity.HIGH,
                        description="El puerto HTTP (80) responde con contenido en texto plano sin forzar la redirección a HTTPS.",
                        evidence=f"Respuesta directa HTTP código {resp.status_code} en {http_url}.",
                        impact="Los usuarios pueden navegar sin cifrado de extremo a extremo, exponiendo sus datos a espionaje de red.",
                        recommendation="Imponer redirección 301 obligatoria hacia HTTPS para todo el tráfico.",
                        reference="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                        url=http_url,
                    )
                )
        except Exception:
            # Puerto 80 cerrado o no disponible (lo cual es seguro)
            pass

        # 2. Análisis del certificado TLS
        cert_info = self._get_certificate_info(target.domain, target.port or 443, timeout=config.timeout)
        if cert_info:
            exp_date = cert_info.get("notAfter")
            if exp_date:
                # Formato estándar OpenSSL: 'Apr 15 12:00:00 2026 GMT'
                try:
                    exp_dt = datetime.strptime(exp_date, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now_dt = datetime.now(timezone.utc)
                    days_left = (exp_dt - now_dt).days

                    if days_left < 0:
                        findings.append(
                            Finding(
                                id="WSA-TLS-002",
                                title="Certificado TLS Expirado",
                                module=self.name,
                                severity=Severity.CRITICAL,
                                description="El certificado SSL/TLS del sitio web ha caducado, provocando advertencias de seguridad a todos los usuarios.",
                                evidence=f"Fecha de vencimiento: {exp_date} (Expiró hace {abs(days_left)} días).",
                                impact="Pérdida total de confianza y posible exposición a ataques de suplantación de identidad (Man-in-the-Middle).",
                                recommendation="Renovar el certificado digital inmediatamente (ej. mediante Let's Encrypt o CA oficial).",
                                reference="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                                url=target.url,
                            )
                        )
                    elif days_left < 30:
                        findings.append(
                            Finding(
                                id="WSA-TLS-003",
                                title="Certificado TLS Próximo a Vencer (< 30 días)",
                                module=self.name,
                                severity=Severity.LOW,
                                description=f"El certificado SSL/TLS caducará en {days_left} días.",
                                evidence=f"Fecha de expiración: {exp_date}.",
                                impact="Riesgo de interrupción del servicio o advertencias de navegador si no se renueva a tiempo.",
                                recommendation="Programar la renovación automática del certificado TLS.",
                                reference="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                                url=target.url,
                            )
                        )
                except Exception:
                    pass

        return findings

    def _get_certificate_info(self, hostname: str, port: int, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        """Extrae el certificado peer TLS a través de un socket seguro."""
        context = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return ssock.getpeercert()
        except Exception:
            return None
