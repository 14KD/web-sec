"""Clase base abstracta para todos los módulos de auditoría de WebSec Auditor."""

from abc import ABC, abstractmethod
from typing import List

from websec.config import ScanConfig
from websec.core.crawler import CrawledPage
from websec.core.http_client import SafeHttpClient
from websec.core.models import Finding, Target


class BaseModule(ABC):
    """Interfaz estándar para módulos pasivos y activos."""

    name: str = "base_module"
    description: str = "Descripción del módulo"
    category: str = "passive"  # "passive" o "active"

    @abstractmethod
    def run(
        self,
        target: Target,
        client: SafeHttpClient,
        crawled_pages: List[CrawledPage],
        config: ScanConfig,
    ) -> List[Finding]:
        """Ejecuta el análisis del módulo sobre el objetivo y retorna la lista de hallazgos encontrados."""
        pass
