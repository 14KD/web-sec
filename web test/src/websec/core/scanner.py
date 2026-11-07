"""Orquestador central del escaneo y ejecución coordinada de módulos."""

from datetime import datetime, timezone
from typing import Dict, List, Type
import time

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage, LightCrawler
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, ScanResult, ScanStats, Target
from websec.core.scoring import SecurityScorer
from websec.modules.base import BaseModule


class SecurityScanner:
    """Orquestador principal que ejecuta el proceso de auditoría."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.target = Target(config.target_url)
        self.registered_modules: Dict[str, BaseModule] = {}

    def register_module(self, module_instance: BaseModule) -> None:
        """Registra un módulo en el catálogo del escáner."""
        self.registered_modules[module_instance.name] = module_instance

    def get_selected_modules(self) -> List[BaseModule]:
        """Obtiene la lista de módulos a ejecutar según la configuración del usuario."""
        if not self.config.active_modules:
            return list(self.registered_modules.values())

        selected_names = {m.strip().lower() for m in self.config.active_modules}
        return [
            m for name, m in self.registered_modules.items()
            if name.lower() in selected_names
        ]

    def run(self) -> ScanResult:
        """Ejecuta la auditoría completa respetando las directrices éticas."""
        if not self.config.has_permission:
            raise PermissionError(
                "Operación cancelada: Se requiere confirmación explícita de autorización "
                "por escrito del propietario antes de auditar este objetivo."
            )

        start_time = datetime.now(timezone.utc)
        all_findings: List[Finding] = []
        crawled_pages: List[CrawledPage] = []

        with SafeHttpClient(self.target, self.config) as client:
            # Fase 1: Rastreo ligero de páginas
            crawler = LightCrawler(self.target, client, self.config)
            crawled_pages = crawler.crawl()

            # Asegurar que al menos la página raíz esté incluida si el crawler no trajo páginas
            if not crawled_pages:
                root_resp = client.get(self.target.url)
                if root_resp:
                    crawled_pages.append(
                        CrawledPage(
                            url=self.target.url,
                            status_code=root_resp.status_code,
                            headers=dict(root_resp.headers),
                            body=root_resp.text,
                        )
                    )

            # Fase 2: Ejecución de módulos seleccionados
            modules_to_run = self.get_selected_modules()
            for module in modules_to_run:
                try:
                    findings = module.run(self.target, client, crawled_pages, self.config)
                    all_findings.extend(findings)
                except Exception:
                    # El fallo controlado de un módulo no detiene la auditoría global
                    continue

            # Cálculo de estadísticas
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            stats = ScanStats(
                pages_crawled=len(crawled_pages),
                requests_made=client.requests_count,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=duration,
            )

        # Fase 3: Evaluación de Puntuación
        score_result = SecurityScorer.calculate(all_findings)

        return ScanResult(
            target=self.target,
            findings=all_findings,
            score=score_result,
            stats=stats,
            crawled_urls=[p.url for p in crawled_pages],
        )
