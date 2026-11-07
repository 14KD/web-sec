"""Pruebas del cliente HTTP seguro y ético con mocks."""

import pytest
import respx
import httpx
from websec.config import ScanConfig
from websec.core.http_client import OutOfScopeError, SafeHttpClient
from websec.core.models import Target


@respx.mock
def test_safe_http_client_in_scope_request(sample_target: Target, sample_config: ScanConfig) -> None:
    respx.get("https://example.com/test").respond(status_code=200, text="OK")

    with SafeHttpClient(sample_target, sample_config) as client:
        resp = client.get("https://example.com/test")
        assert resp is not None
        assert resp.status_code == 200
        assert resp.text == "OK"
        assert client.requests_count == 1


def test_safe_http_client_blocks_out_of_scope(sample_target: Target, sample_config: ScanConfig) -> None:
    with SafeHttpClient(sample_target, sample_config) as client:
        with pytest.raises(OutOfScopeError):
            client.get("https://malicious-target.com/attack")


@respx.mock
def test_safe_http_client_handles_network_error(sample_target: Target, sample_config: ScanConfig) -> None:
    respx.get("https://example.com/error").mock(side_effect=httpx.ConnectError("Connection refused"))

    with SafeHttpClient(sample_target, sample_config) as client:
        resp = client.get("https://example.com/error")
        assert resp is None
