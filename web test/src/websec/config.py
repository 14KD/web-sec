"""Configuración global y opciones de ejecución para WebSec Auditor."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

DATA_DIR = Path(__file__).resolve().parent / "data"

@dataclass
class ScanConfig:
    """Configuración para la ejecución del escaneo de seguridad."""
    target_url: str
    has_permission: bool = False
    rate_limit: float = 2.0  # peticiones por segundo
    timeout: float = 10.0     # segundos por petición
    max_retries: int = 2
    user_agent: str = "WebSecAuditor/1.0 (+https://github.com/websec/websec-auditor; Ethical Scanner)"
    crawl_depth: int = 2
    max_pages: int = 100
    allow_subdomains: bool = False
    active_modules: Optional[List[str]] = None
    output_formats: List[str] = field(default_factory=lambda: ["console", "json", "html", "md"])
    output_dir: Optional[Path] = None
    proxy: Optional[str] = None
    verify_ssl: bool = True
