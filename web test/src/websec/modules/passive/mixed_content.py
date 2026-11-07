"""Módulo pasivo: Detección de contenido mixto (Mixed Content) y verificación de SRI."""

from typing import List
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule


class MixedContentModule(BaseModule):
    """Detecta recursos HTTP en páginas HTTPS y valida Subresource Integrity (SRI) en scripts externos."""

    name = "mixed_content"
    description = "Detecta contenido mixto (HTTP en HTTPS) y librerías externas sin Subresource Integrity (SRI)."
    category = "passive"

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []

        for page in crawled_pages:
            parsed_page = urlparse(page.url)
            if parsed_page.scheme != "https":
                continue

            soup = BeautifulSoup(page.body, "html.parser")

            # 1. Contenido Mixto Activo (Scripts, iframes, stylesheets con http://)
            active_tags = [
                ("script", "src", "Script"),
                ("iframe", "src", "Iframe"),
                ("link", "href", "Hoja de estilo"),
            ]
            for tag_name, attr, label in active_tags:
                for elem in soup.find_all(tag_name):
                    val = elem.get(attr, "")
                    if val.strip().lower().startswith("http://"):
                        findings.append(
                            Finding(
                                id="WSA-MC-001",
                                title=f"Contenido Mixto Activo Detectado ({label})",
                                module=self.name,
                                severity=Severity.HIGH,
                                description=f"Se incluye un recurso ejecutable ({label}) a través de protocolo no seguro HTTP en una página segura HTTPS.",
                                evidence=f"Recurso inseguro: <{tag_name} {attr}='{val}'> en {page.url}",
                                impact="Un atacante intermedio (MitM) puede adulterar el recurso para ejecutar código malicioso en el contexto del sitio.",
                                recommendation="Cargar todos los recursos activos utilizando exclusivamente el esquema `https://`.",
                                reference="https://developer.mozilla.org/es/docs/Web/Security/Mixed_content",
                                url=page.url,
                            )
                        )

            # 2. Contenido Mixto Pasivo (Imágenes, audio, video con http://)
            passive_tags = [("img", "src", "Imagen"), ("audio", "src", "Audio"), ("video", "src", "Video")]
            for tag_name, attr, label in passive_tags:
                for elem in soup.find_all(tag_name):
                    val = elem.get(attr, "")
                    if val.strip().lower().startswith("http://"):
                        findings.append(
                            Finding(
                                id="WSA-MC-002",
                                title=f"Contenido Mixto Pasivo Detectado ({label})",
                                module=self.name,
                                severity=Severity.LOW,
                                description=f"Se carga un recurso multimedia ({label}) vía HTTP en una página HTTPS.",
                                evidence=f"Recurso: <{tag_name} {attr}='{val}'>",
                                impact="Un atacante en la red puede interceptar o reemplazar el contenido multimedia para engañar visualmente al usuario.",
                                recommendation="Migrar las URLs de los recursos estáticos a enlaces HTTPS.",
                                reference="https://developer.mozilla.org/es/docs/Web/Security/Mixed_content",
                                url=page.url,
                            )
                        )

            # 3. Subresource Integrity (SRI) en scripts de terceros
            for script in soup.find_all("script", src=True):
                src = script["src"].strip()
                parsed_src = urlparse(src)
                # Si el script proviene de un dominio externo
                if parsed_src.netloc and parsed_src.netloc.lower() != target.domain:
                    if not script.get("integrity"):
                        findings.append(
                            Finding(
                                id="WSA-MC-003",
                                title="Script de Terceros sin Subresource Integrity (SRI)",
                                module=self.name,
                                severity=Severity.LOW,
                                description=f"Se incluye un script externo desde '{parsed_src.netloc}' sin atributo 'integrity'.",
                                evidence=f"<script src='{src}'>",
                                impact="Si el CDN o proveedor de terceros es comprometido, código adulterado podría ejecutarse sin detección.",
                                recommendation="Incluir el atributo `integrity='sha384-...'` y `crossorigin='anonymous'` en etiquetas de script externas.",
                                reference="https://developer.mozilla.org/es/docs/Web/Security/Subresource_Integrity",
                                url=page.url,
                            )
                        )

        return findings
