"""Modelos de datos para hallazgos, objetivos y resultados de escaneo."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class Severity(str, Enum):
    """Nivel de severidad de un hallazgo según criticidad."""
    CRITICAL = "Crítica"
    HIGH = "Alta"
    MEDIUM = "Media"
    LOW = "Baja"
    INFO = "Informativa"

    @property
    def score_penalty(self) -> int:
        """Penalización sobre el puntaje de 100."""
        penalties = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        return penalties.get(self, 0)

    @property
    def color(self) -> str:
        """Color asociado para salida en terminal."""
        colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "cyan",
        }
        return colors.get(self, "white")


@dataclass
class Finding:
    """Representa un hallazgo de seguridad auditado."""
    id: str
    title: str
    module: str
    severity: Severity
    description: str
    evidence: str
    impact: str
    recommendation: str
    reference: str
    url: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Serializa el hallazgo a formato diccionario."""
        return {
            "id": self.id,
            "title": self.title,
            "module": self.module,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "reference": self.reference,
            "url": self.url,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class Target:
    """Representa el objetivo del escaneo y delimita su alcance."""
    url: str

    def __post_init__(self) -> None:
        if not self.url.startswith(("http://", "https://")):
            self.url = f"https://{self.url}"
        self.parsed = urlparse(self.url)
        self.domain = (self.parsed.hostname or "").lower()
        self.scheme = self.parsed.scheme.lower()
        self.port = self.parsed.port
        self.base_url = f"{self.scheme}://{self.parsed.netloc}"

    def in_scope(self, other_url: str, allow_subdomains: bool = False) -> bool:
        """Verifica si una URL está dentro del alcance ético autorizado."""
        parsed_other = urlparse(other_url)
        other_scheme = (parsed_other.scheme or "").lower()
        if other_scheme and other_scheme not in ("http", "https"):
            return False
        other_host = (parsed_other.hostname or "").lower()
        if not other_host:
            return True  # Rutas relativas se consideran en scope
        if not self.domain:
            return False
        if other_host == self.domain:
            return True
        if allow_subdomains and other_host.endswith(f".{self.domain}"):
            return True
        return False


@dataclass
class ScoreResult:
    """Puntuación y calificación general del sitio auditado."""
    score: int
    grade: str
    breakdown: Dict[str, int]
    summary: str


@dataclass
class ScanStats:
    """Estadísticas de la sesión de escaneo."""
    pages_crawled: int = 0
    requests_made: int = 0
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0


@dataclass
class ScanResult:
    """Resultado consolidado de la auditoría."""
    target: Target
    findings: List[Finding] = field(default_factory=list)
    score: Optional[ScoreResult] = None
    stats: ScanStats = field(default_factory=ScanStats)
    crawled_urls: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serializa el resultado completo a diccionario JSON."""
        return {
            "target": self.target.url,
            "domain": self.target.domain,
            "score": self.score.score if self.score else 0,
            "grade": self.score.grade if self.score else "F",
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "stats": {
                "pages_crawled": self.stats.pages_crawled,
                "requests_made": self.stats.requests_made,
                "duration_seconds": self.stats.duration_seconds,
                "start_time": self.stats.start_time.isoformat(),
                "end_time": self.stats.end_time.isoformat() if self.stats.end_time else None,
            },
            "crawled_urls": self.crawled_urls,
        }
