"""Rastreador web ligero y ético para descubrimiento de enlaces y páginas internas."""

from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set
from urllib.parse import urljoin, urldefrag
from bs4 import BeautifulSoup

from websec.config import ScanConfig
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target

# Extensiones de archivos estáticos que no necesitan rastreo de contenido HTML
STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp3", ".mp4", ".avi", ".mov", ".woff", ".woff2", ".ttf", ".eot",
)


@dataclass
class FormInput:
    """Representa un campo dentro de un formulario HTML."""
    name: str
    input_type: str = "text"
    value: str = ""


@dataclass
class FormInfo:
    """Información analítica de un formulario HTML."""
    action: str
    method: str
    inputs: List[FormInput] = field(default_factory=list)
    has_csrf: bool = False


@dataclass
class CrawledPage:
    """Información recolectada de una página rastreada."""
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    forms: List[FormInfo] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    stylesheets: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)


class LightCrawler:
    """Crawler pasivo y controlado para recopilar páginas dentro del objetivo."""

    def __init__(self, target: Target, client: SafeHttpClient, config: ScanConfig) -> None:
        self.target = target
        self.client = client
        self.config = config

    def crawl(self) -> List[CrawledPage]:
        """Ejecuta el rastreo respetando profundidad máxima y límite de páginas."""
        visited: Set[str] = set()
        queue: deque = deque([(self.target.url, 0)])
        crawled_pages: List[CrawledPage] = []

        while queue and len(visited) < self.config.max_pages:
            current_url, depth = queue.popleft()
            clean_url, _ = urldefrag(current_url)

            if clean_url in visited:
                continue

            # Evitar rastreo directo de binarios pesados
            if clean_url.lower().endswith(STATIC_EXTENSIONS):
                continue

            visited.add(clean_url)
            resp = self.client.get(clean_url)
            if not resp:
                continue

            # Registrar páginas de error (4xx/5xx) para análisis pasivo (ej. error_pages, stack traces), sin rastrear sus enlaces
            if resp.status_code >= 400:
                crawled_pages.append(
                    CrawledPage(
                        url=clean_url,
                        status_code=resp.status_code,
                        headers=dict(resp.headers),
                        body=resp.text,
                    )
                )
                continue

            content_type = resp.headers.get("content-type", "").lower()
            if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                continue

            html = resp.text
            soup = BeautifulSoup(html, "html.parser")

            forms = self._extract_forms(soup, clean_url)
            scripts = self._extract_resources(soup, clean_url, "script", "src")
            stylesheets = self._extract_resources(soup, clean_url, "link", "href")
            links = self._extract_links(soup, clean_url)

            page = CrawledPage(
                url=clean_url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=html,
                forms=forms,
                scripts=scripts,
                stylesheets=stylesheets,
                links=links,
            )
            crawled_pages.append(page)

            # Encolar nuevos enlaces si no hemos llegado a la profundidad límite
            if depth < self.config.crawl_depth:
                for link in links:
                    clean_link, _ = urldefrag(link)
                    if (
                        clean_link not in visited
                        and self.target.in_scope(clean_link, self.config.allow_subdomains)
                        and not clean_link.lower().endswith(STATIC_EXTENSIONS)
                    ):
                        queue.append((clean_link, depth + 1))

        return crawled_pages

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extrae todos los hiperenlaces internos válidos."""
        links: List[str] = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            full_url = urljoin(base_url, href)
            links.append(full_url)
        return links

    def _extract_resources(self, soup: BeautifulSoup, base_url: str, tag_name: str, attr_name: str) -> List[str]:
        """Extrae rutas de recursos cargados en la página."""
        resources: List[str] = []
        for tag in soup.find_all(tag_name):
            val = tag.get(attr_name)
            if val:
                resources.append(urljoin(base_url, val.strip()))
        return resources

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[FormInfo]:
        """Extrae formularios e identifica campos de token anti-CSRF."""
        forms: List[FormInfo] = []
        csrf_keywords = {"csrf", "xsrf", "token", "authenticity_token", "_csrf", "nonce"}

        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action", ""))
            method = form.get("method", "get").upper()
            inputs: List[FormInput] = []
            has_csrf = False

            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                inp_type = inp.get("type", "text").lower()
                val = inp.get("value", "")
                if name:
                    inputs.append(FormInput(name=name, input_type=inp_type, value=val))
                    if any(k in name.lower() for k in csrf_keywords):
                        has_csrf = True

            forms.append(FormInfo(action=action, method=method, inputs=inputs, has_csrf=has_csrf))
        return forms
