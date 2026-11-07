"""Pruebas de la interfaz de línea de comandos (CLI) con CliRunner y mocks."""

from pathlib import Path
import respx
from typer.testing import CliRunner
from websec.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "websec versión 1.0.0" in result.stdout


def test_cli_list_modules() -> None:
    result = runner.invoke(app, ["list-modules"])
    assert result.exit_code == 0
    assert "headers" in result.stdout
    assert "xss" in result.stdout
    assert "sqli" in result.stdout
    assert "cors" in result.stdout


def test_cli_update_db() -> None:
    result = runner.invoke(app, ["update-db"])
    assert result.exit_code == 0
    assert "Base de datos local verificada" in result.stdout


def test_cli_scan_requires_permission() -> None:
    # Cuando no se pasa --i-have-permission y el usuario responde "n" a la confirmación
    result = runner.invoke(app, ["scan", "https://example.com"], input="n\n")
    assert result.exit_code == 1
    assert "Operación abortada" in result.stdout


@respx.mock
def test_cli_scan_successful(tmp_path: Path) -> None:
    respx.get("https://example.com").respond(status_code=200, headers={"Content-Type": "text/html"}, text="<html>Home</html>")
    respx.get(url__regex=r"https://example\.com/.*").respond(status_code=404)
    respx.options(url__regex=r"https://example\.com/.*").respond(status_code=200, headers={"Allow": "GET, HEAD"})

    out_dir = str(tmp_path / "custom_reports")
    result = runner.invoke(
        app,
        [
            "scan",
            "https://example.com",
            "--i-have-permission",
            "--modules", "headers",
            "--rate-limit", "50.0",
            "--output-dir", out_dir,
            "--format", "console,json,html,md",
        ],
    )
    assert result.exit_code == 0
    assert "Auditoría completada con éxito" in result.stdout

    # Verificar que se crearon los reportes esperados
    dest_path = Path(out_dir)
    assert (dest_path / "vulnerabilities.json").exists()
    assert (dest_path / "VULNERABILITIES.md").exists()
    assert (dest_path / "report.json").exists()
    assert (dest_path / "report.html").exists()
