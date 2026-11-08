"""Generador de reporte completo en formato JSON."""

import json
from pathlib import Path
from websec.core.models import ScanResult


class JsonReport:
    """Exporta el resultado completo de la auditoría a archivo JSON estándar."""

    @staticmethod
    def generate(result: ScanResult, output_path: Path) -> None:
        """Escribe el resultado serializado a disco."""
        output_path.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
