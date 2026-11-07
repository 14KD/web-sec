"""Catálogo de módulos activos de WebSec Auditor."""

from websec.modules.active.xss import XssModule
from websec.modules.active.sqli import SqliModule
from websec.modules.active.open_redirect import OpenRedirectModule
from websec.modules.active.cors import CorsModule
from websec.modules.active.clickjacking import ClickjackingModule
from websec.modules.active.csrf import CsrfModule
from websec.modules.active.exposed_files import ExposedFilesModule
from websec.modules.active.content_discovery import ContentDiscoveryModule
from websec.modules.active.subdomains import SubdomainsModule
from websec.modules.active.http_methods import HttpMethodsModule

ACTIVE_MODULES = [
    XssModule,
    SqliModule,
    OpenRedirectModule,
    CorsModule,
    ClickjackingModule,
    CsrfModule,
    ExposedFilesModule,
    ContentDiscoveryModule,
    SubdomainsModule,
    HttpMethodsModule,
]

__all__ = [
    "XssModule",
    "SqliModule",
    "OpenRedirectModule",
    "CorsModule",
    "ClickjackingModule",
    "CsrfModule",
    "ExposedFilesModule",
    "ContentDiscoveryModule",
    "SubdomainsModule",
    "HttpMethodsModule",
    "ACTIVE_MODULES",
]
