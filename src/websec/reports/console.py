"""Presentación visual en consola de la auditoría utilizando Rich."""

from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from websec.core.models import ScanResult, Severity


class ConsoleReport:
    """Genera tablas visuales enriquecidas y resúmenes ejecutivos en la terminal."""

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()

    def print_banner(self) -> None:
        """Muestra el banner de inicio con aviso ético obligatorio."""
        banner_text = Text()
        banner_text.append("🛡️  WebSec Auditor v1.0  🛡️\n", style="bold cyan")
        banner_text.append("Herramienta Profesional de Auditoría de Seguridad Web Ética y No Destructiva\n", style="italic")
        banner_text.append("\n[!] AVISO LEGAL: Esta herramienta debe ejecutarse ÚNICAMENTE en sitios propios\n", style="bold yellow")
        banner_text.append("o bajo autorización expresa y por escrito del propietario del dominio.\n", style="yellow")
        self.console.print(Panel(banner_text, border_style="cyan"))

    def print_results(self, result: ScanResult) -> None:
        """Imprime el resumen de hallazgos, score y desglose."""
        # 1. Panel de Calificación y Score
        score = result.score.score if result.score else 0
        grade = result.score.grade if result.score else "F"
        summary = result.score.summary if result.score else ""

        grade_style = "bold green" if grade in ("A+", "A") else ("bold yellow" if grade in ("B", "C") else "bold red")

        score_text = Text()
        score_text.append(f"CALIFICACIÓN FINAL: {grade}  ", style=grade_style)
        score_text.append(f"PUNTUACIÓN: {score}/100\n", style="bold white")
        score_text.append(f"{summary}\n\n", style="italic white")
        score_text.append(f"Objetivo: {result.target.url} | Páginas analizadas: {result.stats.pages_crawled} | Duración: {result.stats.duration_seconds:.2f}s", style="dim")

        self.console.print(Panel(score_text, title="📊 Evaluación Global de Seguridad", border_style=grade_style))

        # 2. Tabla de Resumen por Severidad
        breakdown_table = Table(title="Desglose de Hallazgos por Nivel de Riesgo", header_style="bold magenta")
        breakdown_table.add_column("Severidad", justify="center")
        breakdown_table.add_column("Cantidad", justify="center")
        breakdown_table.add_column("Penalización Total", justify="center")

        if result.score:
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                count = result.score.breakdown.get(sev.value, 0)
                pen = count * sev.score_penalty
                breakdown_table.add_row(
                    f"[{sev.color}]{sev.value}[/{sev.color}]",
                    str(count),
                    f"-{pen} pts" if pen > 0 else "0 pts",
                )

        self.console.print(breakdown_table)

        # 3. Tabla detallada de Hallazgos
        if result.findings:
            findings_table = Table(title="Detalle de Vulnerabilidades Detectadas", header_style="bold blue")
            findings_table.add_column("ID", style="dim", width=12)
            findings_table.add_column("Severidad", justify="center", width=12)
            findings_table.add_column("Título", style="bold white", width=35)
            findings_table.add_column("Módulo", style="cyan", width=15)
            findings_table.add_column("Recomendación Sugerida", width=40)

            for f in result.findings:
                findings_table.add_row(
                    f.id,
                    f"[{f.severity.color}]{f.severity.value}[/{f.severity.color}]",
                    f.title,
                    f.module,
                    f.recommendation,
                )
            self.console.print(findings_table)
        else:
            self.console.print(Panel("[bold green]✅ No se detectaron vulnerabilidades en los módulos ejecutados.[/bold green]"))
