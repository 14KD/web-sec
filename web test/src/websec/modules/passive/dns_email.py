"""Módulo pasivo: Auditoría de registros DNS de seguridad y correo (SPF, DMARC, DKIM, CAA)."""

from typing import List, Optional
import dns.resolver

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule


class DnsEmailModule(BaseModule):
    """Verifica políticas de seguridad DNS para prevención de spoofing de correo y emisión no autorizada de certificados."""

    name = "dns_email"
    description = "Audita registros DNS de correo (SPF, DMARC) y restricciones de autoridades de certificación (CAA)."
    category = "passive"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []
        domain = target.domain

        # 1. Registro SPF (TXT en dominio principal)
        spf_record = self._get_txt_record(domain, "v=spf1")
        if not spf_record:
            findings.append(
                Finding(
                    id="WSA-DNS-001",
                    title="Registro SPF (Sender Policy Framework) Ausente",
                    module=self.name,
                    severity=Severity.MEDIUM,
                    description="El dominio no cuenta con registro SPF para autenticar qué servidores están autorizados a enviar correo electrónico en su nombre.",
                    evidence=f"No se encontró registro TXT con 'v=spf1' para el dominio {domain}.",
                    impact="Facilita ataques de suplantación de identidad (Email Spoofing) y campañas de phishing utilizando el nombre del dominio.",
                    recommendation="Configurar un registro TXT con la política SPF adecuada (ej. `v=spf1 mx -all`).",
                    reference="https://www.rfc-editor.org/rfc/rfc7208",
                    url=f"dns://{domain}",
                )
            )
        else:
            if "+all" in spf_record:
                findings.append(
                    Finding(
                        id="WSA-DNS-002",
                        title="Política SPF Excesivamente Permisiva (+all)",
                        module=self.name,
                        severity=Severity.HIGH,
                        description="El registro SPF contiene la directiva `+all`, lo cual autoriza explícitamente a cualquier servidor de internet a enviar correo bajo este dominio.",
                        evidence=f"Registro SPF: {spf_record}",
                        impact="Invalida la protección de SPF, permitiendo suplantación de correos corporativos sin advertencias de autenticación.",
                        recommendation="Reemplazar `+all` por `-all` (rechazo estricto) o `~all` (softfail).",
                        reference="https://www.rfc-editor.org/rfc/rfc7208",
                        url=f"dns://{domain}",
                    )
                )

        # 2. Registro DMARC (TXT en _dmarc.dominio)
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_record = self._get_txt_record(dmarc_domain, "v=dmarc1")
        if not dmarc_record:
            findings.append(
                Finding(
                    id="WSA-DNS-003",
                    title="Registro DMARC Ausente",
                    module=self.name,
                    severity=Severity.MEDIUM,
                    description="No se detectó registro DMARC, impidiendo al dominio especificar cómo actuar ante correos que fallen SPF o DKIM.",
                    evidence=f"Consulta TXT a {dmarc_domain} no devolvió registro con 'v=DMARC1'.",
                    impact="Mayor vulnerabilidad ante fraudes de correo, falta de visibilidad y reportes de suplantación de marca.",
                    recommendation="Publicar un registro DMARC en `_dmarc.{domain}` (ej. `v=DMARC1; p=reject; rua=mailto:dmarc@{domain}`).",
                    reference="https://www.rfc-editor.org/rfc/rfc7489",
                    url=f"dns://{dmarc_domain}",
                )
            )
        else:
            if "p=none" in dmarc_record.lower():
                findings.append(
                    Finding(
                        id="WSA-DNS-004",
                        title="Política DMARC Débil (p=none)",
                        module=self.name,
                        severity=Severity.LOW,
                        description="El registro DMARC está configurado en modo monitoreo exclusivo (`p=none`), sin instruir el rechazo ni cuarentena de correos falsificados.",
                        evidence=f"DMARC: {dmarc_record}",
                        impact="Los correos que no superan la autenticación siguen siendo entregados a la bandeja de entrada del destinatario.",
                        recommendation="Migrar progresivamente la política hacia `p=quarantine` o `p=reject`.",
                        reference="https://dmarc.org/overview/",
                        url=f"dns://{dmarc_domain}",
                    )
                )

        # 3. Registro CAA (Certification Authority Authorization)
        has_caa = self._check_caa_record(domain)
        if not has_caa:
            findings.append(
                Finding(
                    id="WSA-DNS-005",
                    title="Registro DNS CAA Ausente",
                    module=self.name,
                    severity=Severity.LOW,
                    description="El dominio no especifica qué Autoridades de Certificación (CA) tienen permiso para emitir certificados SSL/TLS para su nombre.",
                    evidence=f"No se detectaron registros CAA para el dominio {domain}.",
                    impact="Cualquier CA pública comprometida podría emitir un certificado fraudulento para este dominio sin infringir controles DNS.",
                    recommendation="Añadir registros CAA autorizando exclusivamente a las CAs utilizadas (ej. `0 issue \"letsencrypt.org\"`).",
                    reference="https://developer.mozilla.org/es/docs/Web/Security/Certificate_Authority_Authorization",
                    url=f"dns://{domain}",
                )
            )

        return findings

    def _get_txt_record(self, name: str, prefix_match: str) -> Optional[str]:
        """Consulta registros TXT y busca concordancia de prefijo."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0
            answers = resolver.resolve(name, "TXT")
            for rdata in answers:
                txt_content = "".join([part.decode("utf-8", errors="ignore") for part in rdata.strings])
                if prefix_match.lower() in txt_content.lower():
                    return txt_content
        except Exception:
            return None
        return None

    def _check_caa_record(self, name: str) -> bool:
        """Comprueba si existen registros CAA configurados."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3.0
            resolver.lifetime = 3.0
            answers = resolver.resolve(name, "CAA")
            return len(answers) > 0
        except Exception:
            return False
