"""Interfaz de línea de comandos (CLI) principal de WebSec Auditor con Typer y Rich."""

from datetime import datetime
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.table import Table

from websec import __app_name__, __version__
from websec.config import DATA_DIR, ScanConfig
from websec.core.models import Target
from websec.core.scanner import SecurityScanner
from websec.modules import ALL_MODULES, MODULE_CATALOG
from websec.reports.console import ConsoleReport
from websec.reports.html_report import HtmlReport
from websec.reports.json_report import JsonReport
from websec.reports.vulnerabilities_report import VulnerabilitiesReport

app = typer.Typer(
    name=__app_name__,
    help="🛡️ WebSec Auditor: Herramienta profesional de auditoría de seguridad web ética y no destructiva.",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]{__app_name__}[/bold cyan] versión [bold green]{__version__}[/bold green]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Muestra la versión de la herramienta y finaliza.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    pass


@app.command("scan")
def scan_command(
    url: str = typer.Argument(..., help="URL objetivo para auditar (ej. https://ejemplo.com)"),
    i_have_permission: bool = typer.Option(
        False,
        "--i-have-permission",
        help="Confirmación explícita de autorización por escrito del propietario para auditar el objetivo.",
    ),
    modules: Optional[str] = typer.Option(
        None,
        "--modules",
        "-m",
        help="Lista de módulos separados por comas (ej. headers,tls,xss,sqli,cors).",
    ),
    depth: int = typer.Option(
        2,
        "--depth",
        "-d",
        min=0,
        max=5,
        help="Profundidad máxima de rastreo de páginas internas (defecto: 2).",
    ),
    rate_limit: float = typer.Option(
        2.0,
        "--rate-limit",
        "-r",
        min=0.1,
        max=50.0,
        help="Límite ético de peticiones por segundo (defecto: 2.0).",
    ),
    output_formats: str = typer.Option(
        "console,json,html,md",
        "--format",
        "-f",
        help="Formatos de salida separados por comas (console, json, html, md).",
    ),
    output_dir: Optional[str] = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Directorio personalizado para almacenar los reportes.",
    ),
    allow_subdomains: bool = typer.Option(
        False,
        "--allow-subdomains",
        help="Permite rastrear y considerar en alcance los subdominios del objetivo.",
    ),
    timeout: float = typer.Option(
        10.0,
        "--timeout",
        help="Tiempo de espera en segundos para cada petición HTTP (defecto: 10.0s).",
    ),
) -> None:
    """Ejecuta una auditoría de seguridad exhaustiva, ética y no destructiva sobre un objetivo."""
    console_report = ConsoleReport(console)
    console_report.print_banner()

    # Verificación obligatoria de autorización ética
    if not i_have_permission:
        confirmed = typer.confirm(
            "⚠️ ¿Confirma que dispone de autorización explícita y por escrito para analizar este dominio?",
            default=False,
        )
        if not confirmed:
            console.print("\n[bold red]❌ Operación abortada:[/bold red] WebSec Auditor no puede auditar sitios sin consentimiento expreso.\n")
            raise typer.Exit(code=1)

    target = Target(url)
    active_mods_list = [m.strip().lower() for m in modules.split(",")] if modules else None

    # Configuración de salida
    formats = [f.strip().lower() for f in output_formats.split(",")]
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    reports_folder = Path(output_dir) if output_dir else Path("reports") / f"{target.domain}-{timestamp_str}"
    reports_folder.mkdir(parents=True, exist_ok=True)

    config = ScanConfig(
        target_url=target.url,
        has_permission=True,
        rate_limit=rate_limit,
        timeout=timeout,
        crawl_depth=depth,
        allow_subdomains=allow_subdomains,
        active_modules=active_mods_list,
        output_formats=formats,
        output_dir=reports_folder,
    )

    scanner = SecurityScanner(config)

    # Registrar todos los módulos disponibles
    for mod_cls in ALL_MODULES:
        scanner.register_module(mod_cls())

    selected_count = len(scanner.get_selected_modules())
    console.print(f"[bold green]▶ Iniciando auditoría sobre:[/bold green] [white]{target.url}[/white]")
    console.print(f"[dim]Módulos activos: {selected_count} | Rate Limit: {rate_limit} req/s | Profundidad: {depth}[/dim]\n")

    with console.status("[bold cyan]Ejecutando pruebas de seguridad y rastreo pasivo/activo...[/bold cyan]", spinner="dots"):
        result = scanner.run()

    # Generación de reportes
    if "console" in formats:
        console_report.print_results(result)

    if "json" in formats:
        json_file = reports_folder / "report.json"
        JsonReport.generate(result, json_file)

    if "html" in formats:
        html_file = reports_folder / "report.html"
        HtmlReport.generate(result, html_file)

    # Generar SIEMPRE los dos archivos dedicados de vulnerabilidades
    vuln_json = reports_folder / "vulnerabilities.json"
    vuln_md = reports_folder / "VULNERABILITIES.md"
    VulnerabilitiesReport.generate_json(result, vuln_json)
    VulnerabilitiesReport.generate_markdown(result, vuln_md)

    console.print(f"\n[bold green]✔ Auditoría completada con éxito.[/bold green]")
    console.print(f"[bold cyan]📁 Archivos y reportes generados en:[/bold cyan] {reports_folder.resolve()}\n")
    console.print(f"  • [yellow]vulnerabilities.json[/yellow] (Integración con herramientas/CI)")
    console.print(f"  • [yellow]VULNERABILITIES.md[/yellow]  (Para issues de GitHub / tickets)")
    if "html" in formats:
        console.print(f"  • [white]report.html[/white]         (Reporte visual interactivo)")
    if "json" in formats:
        console.print(f"  • [white]report.json[/white]         (Resultado crudo completo)")


@app.command("list-modules")
def list_modules_command() -> None:
    """Lista todos los módulos pasivos y activos disponibles en WebSec Auditor."""
    table = Table(title="🛡️ Catálogo de Módulos de WebSec Auditor", header_style="bold cyan")
    table.add_column("Nombre", style="bold white", width=18)
    table.add_column("Categoría", justify="center", width=12)
    table.add_column("Descripción", width=55)

    for mod_cls in ALL_MODULES:
        cat_color = "green" if mod_cls.category == "passive" else "yellow"
        table.add_row(
            mod_cls.name,
            f"[{cat_color}]{mod_cls.category.upper()}[/{cat_color}]",
            mod_cls.description,
        )

    console.print(table)


@app.command("update-db")
def update_db_command() -> None:
    """Verifica y actualiza la base de datos local de componentes vulnerables y CVEs."""
    db_file = DATA_DIR / "vulnerable_libs.json"
    console.print("[cyan]Verificando base de datos local de CVEs y componentes...[/cyan]")
    if db_file.exists():
        console.print(f"[bold green]✔ Base de datos local verificada:[/bold green] {db_file.resolve()}")
    else:
        console.print("[bold red]⚠ No se encontró el archivo vulnerable_libs.json local.[/bold red]")
