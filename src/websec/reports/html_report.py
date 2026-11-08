"""Generador de reporte interactivo y autocontenido en HTML."""

from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from websec.core.models import ScanResult

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


class HtmlReport:
    """Renderiza una plantilla HTML moderna con gráficos de severidad, filtros dinámicos y soporte de impresión."""

    @staticmethod
    def generate(result: ScanResult, output_path: Path) -> None:
        """Compila y guarda el reporte HTML."""
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
        )
        template = env.get_template("report.html.j2")
        rendered_html = template.render(result=result)
        output_path.write_text(rendered_html, encoding="utf-8")
