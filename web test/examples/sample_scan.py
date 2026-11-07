"""Ejemplo programático de uso del motor WebSec Auditor en scripts de Python."""

from websec.config import ScanConfig
from websec.core.scanner import SecurityScanner
from websec.modules import ALL_MODULES
from websec.reports.console import ConsoleReport

def run_programmatic_audit() -> None:
    # 1. Definir configuración con consentimiento ético explícito
    config = ScanConfig(
        target_url="https://example.com",
        has_permission=True,
        rate_limit=2.0,
        crawl_depth=1,
        active_modules=["headers", "cookies", "cors"],
    )

    # 2. Inicializar escáner y registrar módulos
    scanner = SecurityScanner(config)
    for mod_cls in ALL_MODULES:
        scanner.register_module(mod_cls())

    # 3. Ejecutar auditoría
    print(f"Iniciando auditoría sobre {config.target_url}...")
    result = scanner.run()

    # 4. Mostrar resultados en consola
    console_report = ConsoleReport()
    console_report.print_results(result)

if __name__ == "__main__":
    run_programmatic_audit()
