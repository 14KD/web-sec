"""Pruebas drásticas de resiliencia y Chaos Engineering (Fault Injection).

Simula condiciones de red adversas extremas:
- Caída total de conexión / TCP RST
- Timeouts agresivos y caídas de servidor
- Bucles infinitos de redirección
- Respuestas masivas / Zip bomb simulation
- Respuestas con errores internos 500/502/503 masivos
"""

import httpx
import pytest
import respx
from websec.config import ScanConfig
from websec.core.http_client import SafeHttpClient, OutOfScopeError
from websec.core.models import Target
from websec.core.scanner import SecurityScanner
from websec.modules import ALL_MODULES


@respx.mock
def test_chaos_total_timeout_resilience() -> None:
    """El escáner sobrevive a timeouts persistentes en cada petición sin crashear."""
    respx.route().mock(side_effect=httpx.ReadTimeout("Simulated network freeze/timeout"))

    target_url = "https://chaos-timeout.example"
    config = ScanConfig(
        target_url=target_url,
        has_permission=True,
        timeout=0.1,
        max_retries=0,
        rate_limit=100.0,
    )
    scanner = SecurityScanner(config)
    for mod_cls in ALL_MODULES:
        scanner.register_module(mod_cls())

    result = scanner.run()

    assert result is not None
    assert result.target.url == target_url
    assert result.score is not None
    assert result.stats.requests_made >= 0


@respx.mock
def test_chaos_connection_drop_resilience() -> None:
    """El escáner tolera rechazos bruscos de conexión (TCP RST / ConnectError)."""
    respx.route().mock(side_effect=httpx.ConnectError("Connection refused by peer"))

    target_url = "https://chaos-drop.example"
    config = ScanConfig(
        target_url=target_url,
        has_permission=True,
        timeout=0.1,
        max_retries=0,
        rate_limit=100.0,
    )
    scanner = SecurityScanner(config)
    for mod_cls in ALL_MODULES:
        scanner.register_module(mod_cls())

    result = scanner.run()

    assert result is not None
    assert result.score is not None
    assert result.score.score >= 0


@respx.mock
def test_chaos_infinite_redirect_loop() -> None:
    """SafeHttpClient maneja bucles de redirección (A -> B -> A) sin recursión infinita."""
    respx.get("https://chaos-loop.example/page1").respond(
        status_code=302,
        headers={"Location": "https://chaos-loop.example/page2"},
    )
    respx.get("https://chaos-loop.example/page2").respond(
        status_code=302,
        headers={"Location": "https://chaos-loop.example/page1"},
    )

    target = Target("https://chaos-loop.example")
    config = ScanConfig(target_url=target.url, has_permission=True, rate_limit=100.0)

    with SafeHttpClient(target, config) as client:
        # httpx corta el bucle de redirecciones excedidas lanzando TooManyRedirects
        # SafeHttpClient debe capturarlo limpiamente y retornar None
        resp = client.get("https://chaos-loop.example/page1")
        assert resp is None


@respx.mock
def test_chaos_massive_response_body() -> None:
    """El cliente y módulos procesan respuestas con cargas masivas de datos sin asfixiar la memoria."""
    massive_text = "<html><body>" + ("<p>Data payload spam</p>\n" * 10000) + "</body></html>"
    respx.get("https://chaos-massive.example").respond(
        status_code=200,
        headers={"Content-Type": "text/html"},
        text=massive_text,
    )
    respx.route().respond(status_code=404)

    target_url = "https://chaos-massive.example"
    config = ScanConfig(
        target_url=target_url,
        has_permission=True,
        rate_limit=100.0,
        crawl_depth=1,
    )
    scanner = SecurityScanner(config)
    for mod_cls in ALL_MODULES:
        scanner.register_module(mod_cls())

    result = scanner.run()
    assert result is not None
    assert len(result.crawled_urls) >= 1


@respx.mock
def test_chaos_internal_server_errors_across_all_modules() -> None:
    """Respuestas continuas 500/502/503 son manejadas de forma segura por todos los módulos."""
    respx.get("https://chaos-errors.example").respond(
        status_code=500,
        headers={"Content-Type": "text/html"},
        text="<html>500 Internal Server Error</html>",
    )
    respx.route().respond(status_code=502, text="Bad Gateway")

    target_url = "https://chaos-errors.example"
    config = ScanConfig(
        target_url=target_url,
        has_permission=True,
        rate_limit=100.0,
        crawl_depth=1,
    )
    scanner = SecurityScanner(config)
    for mod_cls in ALL_MODULES:
        scanner.register_module(mod_cls())

    result = scanner.run()
    assert result is not None
    assert result.score is not None
