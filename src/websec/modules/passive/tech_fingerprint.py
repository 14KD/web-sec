"""Módulo pasivo: Identificación de tecnologías y comprobación contra base de CVEs conocidos."""

import json
from pathlib import Path
import re
from typing import Dict, List, Optional
from bs4 import BeautifulSoup
from packaging import version

from websec.config import DATA_DIR, ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Severity, Target
from websec.modules.base import BaseModule


class TechFingerprintModule(BaseModule):
    """Detecta frameworks, CMS y librerías y busca vulnerabilidades reportadas en la base local."""

    name = "tech_fingerprint"
    description = "Identifica CMS, librerías frontend y backend, contrastando versiones con CVEs conocidos."
    category = "passive"

    def __init__(self) -> None:
        self.cve_db = self._load_cve_db()

    def _load_cve_db(self) -> List[Dict[str, str]]:
        db_path = DATA_DIR / "vulnerable_libs.json"
        if db_path.exists():
            try:
                data = json.loads(db_path.read_text(encoding="utf-8"))
                return data.get("libraries", [])
            except Exception:
                return []
        return []

    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        findings: List[Finding] = []
        detected_techs: Dict[str, str] = {}  # nombre_tech -> versión o "detectado"

        for page in crawled_pages:
            soup = BeautifulSoup(page.body, "html.parser")

            # 1. Meta generator
            for meta in soup.find_all("meta", attrs={"name": re.compile(r"generator", re.I)}):
                content = meta.get("content", "")
                if "wordpress" in content.lower():
                    m = re.search(r"wordpress\s*([\d\.]+)", content, re.I)
                    detected_techs["wordpress"] = m.group(1) if m else "detectado"

            # 2. Scripts (jQuery, Bootstrap, Angular, React...)
            for script in soup.find_all("script", src=True):
                src = script["src"]
                # jQuery: jquery-3.4.1.min.js o jquery.min.js?v=3.4.1
                jq_match = re.search(r"jquery[.-]([\d\.]+)(?:\.min)?\.js", src, re.I)
                if jq_match:
                    detected_techs["jquery"] = jq_match.group(1)

                # Bootstrap: bootstrap-4.2.1.min.js
                bs_match = re.search(r"bootstrap[.-]([\d\.]+)(?:\.min)?\.js", src, re.I)
                if bs_match:
                    detected_techs["bootstrap"] = bs_match.group(1)

                # AngularJS: angular-1.5.8.js
                ng_match = re.search(r"angular[.-]([\d\.]+)(?:\.min)?\.js", src, re.I)
                if ng_match:
                    detected_techs["angularjs"] = ng_match.group(1)

            # 3. Cabeceras HTTP
            headers = {k.lower(): v for k, v in page.headers.items()}
            if "x-powered-by" in headers:
                val = headers["x-powered-by"]
                if "php" in val.lower():
                    detected_techs["php"] = val
                if "express" in val.lower():
                    detected_techs["express"] = val

        # Cotejar contra base local de librerías vulnerables
        for lib in self.cve_db:
            lib_name = lib["name"].lower()
            if lib_name in detected_techs:
                detected_ver = detected_techs[lib_name]
                if detected_ver != "detectado":
                    try:
                        if version.parse(detected_ver) < version.parse(lib["vulnerable_below"]):
                            sev_map = {
                                "Crítica": Severity.CRITICAL,
                                "Alta": Severity.HIGH,
                                "Media": Severity.MEDIUM,
                                "Baja": Severity.LOW,
                            }
                            sev = sev_map.get(lib.get("severity", "Media"), Severity.MEDIUM)
                            findings.append(
                                Finding(
                                    id=f"WSA-CVE-{lib['cve'].replace('-', '')}",
                                    title=f"{lib['title']} ({detected_ver})",
                                    module=self.name,
                                    severity=sev,
                                    description=f"{lib['description']} Versión detectada: {detected_ver}. Requiere >= {lib['vulnerable_below']}.",
                                    evidence=f"Tecnología: {lib_name} v{detected_ver}. Referencia: {lib['cve']}",
                                    impact="Exposición a fallos de seguridad documentados y exploits públicos.",
                                    recommendation=lib["recommendation"],
                                    reference=f"https://nvd.nist.gov/vuln/detail/{lib['cve']}",
                                    url=target.url,
                                )
                            )
                    except Exception:
                        pass

        # Hallazgo informativo de tecnologías detectadas
        if detected_techs:
            tech_list = ", ".join(f"{k} ({v})" for k, v in detected_techs.items())
            findings.append(
                Finding(
                    id="WSA-TECH-001",
                    title="Componentes y Tecnologías Web Detectadas",
                    module=self.name,
                    severity=Severity.INFO,
                    description="Se identificaron tecnologías, CMS y librerías utilizadas por la aplicación.",
                    evidence=f"Tecnologías detectadas: {tech_list}",
                    impact="Permite conocer el inventario tecnológico y mantener las dependencias al día.",
                    recommendation="Monitorear el ciclo de vida de los componentes y aplicar parches de seguridad periódicos.",
                    reference="https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
                    url=target.url,
                )
            )

        return findings
