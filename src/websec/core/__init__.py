"""Núcleo del sistema WebSec Auditor."""

from websec.core.models import Finding, ScanResult, Severity, Target
from websec.core.http_client import SafeHttpClient, OutOfScopeError
from websec.core.crawler import LightCrawler, CrawledPage
from websec.core.scoring import SecurityScorer
from websec.core.scanner import SecurityScanner

__all__ = [
    "Finding",
    "ScanResult",
    "Severity",
    "Target",
    "SafeHttpClient",
    "OutOfScopeError",
    "LightCrawler",
    "CrawledPage",
    "SecurityScorer",
    "SecurityScanner",
]
