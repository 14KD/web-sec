"""Cliente HTTP ético con rate limiting, timeouts, reintentos y control de alcance."""

import time
from typing import Any, Dict, Optional
import httpx

from websec.config import ScanConfig
from websec.core.models import Target


class OutOfScopeError(Exception):
    """Excepción lanzada cuando se intenta realizar una petición fuera del alcance autorizado."""
    pass


class SafeHttpClient:
    """Cliente HTTP con protecciones éticas: limitación de velocidad y delimitación estricta de alcance."""

    def __init__(self, target: Target, config: ScanConfig) -> None:
        self.target = target
        self.config = config
        self._delay_between_requests = 1.0 / max(0.1, config.rate_limit)
        self._last_request_time = 0.0
        self.requests_count = 0

        # Configuración de headers estándar
        self.headers = {
            "User-Agent": config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        }

        # Inicialización del cliente httpx sincrónico
        transport = httpx.HTTPTransport(
            retries=config.max_retries,
            verify=config.verify_ssl,
        )
        self.client = httpx.Client(
            transport=transport,
            timeout=config.timeout,
            headers=self.headers,
            follow_redirects=True,
            proxy=config.proxy,
        )

    def _enforce_rate_limit(self) -> None:
        """Aplica la pausa requerida para respetar el límite de peticiones por segundo."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._delay_between_requests:
            time.sleep(self._delay_between_requests - elapsed)
        self._last_request_time = time.time()

    def _verify_scope(self, url: str) -> None:
        """Valida que la URL esté estrictamente dentro del alcance del objetivo."""
        if not self.target.in_scope(url, allow_subdomains=self.config.allow_subdomains):
            raise OutOfScopeError(f"Intento de acceso bloqueado fuera de alcance: {url}")

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: Optional[bool] = None,
    ) -> Optional[httpx.Response]:
        """Envía una petición HTTP segura respetando scope, rate limit y reintentos."""
        # Convertir URL relativa si es necesario
        if not url.startswith(("http://", "https://")):
            url = f"{self.target.base_url.rstrip('/')}/{url.lstrip('/')}"

        self._verify_scope(url)
        self._enforce_rate_limit()

        req_headers = dict(self.headers)
        if headers:
            req_headers.update(headers)

        redirects = follow_redirects if follow_redirects is not None else True

        try:
            self.requests_count += 1
            response = self.client.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                json=json,
                headers=req_headers,
                follow_redirects=redirects,
            )
            return response
        except (httpx.RequestError, httpx.HTTPStatusError):
            return None

    def get(self, url: str, **kwargs: Any) -> Optional[httpx.Response]:
        """Acceso rápido a GET."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Optional[httpx.Response]:
        """Acceso rápido a POST."""
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Optional[httpx.Response]:
        """Acceso rápido a HEAD."""
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Optional[httpx.Response]:
        """Acceso rápido a OPTIONS."""
        return self.request("OPTIONS", url, **kwargs)

    def close(self) -> None:
        """Cierra el cliente y libera recursos."""
        self.client.close()

    def __enter__(self) -> "SafeHttpClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
