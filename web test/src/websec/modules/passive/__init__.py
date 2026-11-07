"""Catálogo de módulos pasivos de WebSec Auditor."""

from websec.modules.passive.headers import HeadersModule
from websec.modules.passive.tls import TlsModule
from websec.modules.passive.cookies import CookiesModule
from websec.modules.passive.mixed_content import MixedContentModule
from websec.modules.passive.tech_fingerprint import TechFingerprintModule
from websec.modules.passive.dns_email import DnsEmailModule
from websec.modules.passive.error_pages import ErrorPagesModule

PASSIVE_MODULES = [
    HeadersModule,
    TlsModule,
    CookiesModule,
    MixedContentModule,
    TechFingerprintModule,
    DnsEmailModule,
    ErrorPagesModule,
]

__all__ = [
    "HeadersModule",
    "TlsModule",
    "CookiesModule",
    "MixedContentModule",
    "TechFingerprintModule",
    "DnsEmailModule",
    "ErrorPagesModule",
    "PASSIVE_MODULES",
]
