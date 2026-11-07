"""Pruebas del crawler ligero con respuestas HTML simuladas."""

import respx
from websec.config import ScanConfig
from websec.core.crawler import LightCrawler
from websec.core.http_client import SafeHttpClient
from websec.core.models import Target


@respx.mock
def test_crawler_extracts_links_and_forms(sample_target: Target, sample_config: ScanConfig) -> None:
    html_home = """
    <html>
      <head>
        <link rel="stylesheet" href="/style.css">
        <script src="/app.js"></script>
      </head>
      <body>
        <a href="/about">About</a>
        <a href="https://external.com/out">External</a>
        <form action="/login" method="POST">
          <input type="text" name="username">
          <input type="password" name="password">
          <input type="hidden" name="csrf_token" value="xyz123">
        </form>
      </body>
    </html>
    """
    html_about = "<html><body><h1>About Us</h1><a href='/'>Home</a></body></html>"

    respx.get("https://example.com").respond(status_code=200, headers={"Content-Type": "text/html"}, text=html_home)
    respx.get("https://example.com/about").respond(status_code=200, headers={"Content-Type": "text/html"}, text=html_about)

    with SafeHttpClient(sample_target, sample_config) as client:
        crawler = LightCrawler(sample_target, client, sample_config)
        pages = crawler.crawl()

        assert len(pages) == 2
        root_page = next(p for p in pages if p.url == "https://example.com")
        assert len(root_page.forms) == 1
        assert root_page.forms[0].has_csrf is True
        assert len(root_page.scripts) == 1
        assert len(root_page.stylesheets) == 1
