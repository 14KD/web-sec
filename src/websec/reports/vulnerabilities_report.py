"""Generador de archivos dedicados de vulnerabilidades (vulnerabilities.json y VULNERABILITIES.md)."""

import json
from pathlib import Path
from typing import Dict, List
from websec.core.models import Finding, ScanResult, Severity


class VulnerabilitiesReport:
    """Genera artefactos específicos de vulnerabilidades orientados a integración CI/CD e issues de desarrollo."""

    @staticmethod
    def generate_json(result: ScanResult, output_path: Path) -> None:
        """Exporta lista plana estructurada de vulnerabilidades a vulnerabilities.json."""
        data = {
            "target": result.target.url,
            "domain": result.target.domain,
            "scan_date": result.stats.start_time.isoformat(),
            "total_findings": len(result.findings),
            "score": result.score.score if result.score else 0,
            "grade": result.score.grade if result.score else "F",
            "findings": [f.to_dict() for f in result.findings],
        }
        output_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def generate_markdown(result: ScanResult, output_path: Path) -> None:
        """Genera documento VULNERABILITIES.md agrupado por severidad para issues de GitHub o tickets Jira."""
        lines: List[str] = [
            f"# Reporte de Vulnerabilidades - {result.target.domain}",
            "",
            f"> **Objetivo:** {result.target.url}  ",
            f"> **Calificación:** {result.score.grade if result.score else 'F'} ({result.score.score if result.score else 0}/100)  ",
            f"> **Fecha:** {result.stats.start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"> **Total de hallazgos:** {len(result.findings)}",
            "",
            "---",
            "",
            "## Resumen de Severidad",
            "",
            "| Nivel | Cantidad |",
            "| :--- | :--- |",
        ]

        if result.score:
            for sev_name, count in result.score.breakdown.items():
                lines.append(f"| **{sev_name}** | {count} |")

        lines.extend([
            "",
            "---",
            "",
            "## Detalle de Hallazgos por Criticidad",
            "",
        ])

        # Agrupar hallazgos por severidad
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        findings_by_sev: Dict[Severity, List[Finding]] = {s: [] for s in order}
        for f in result.findings:
            if f.severity in findings_by_sev:
                findings_by_sev[f.severity].append(f)

        for sev in order:
            group = findings_by_sev[sev]
            if not group:
                continue

            lines.extend([
                f"### {sev.value} ({len(group)})",
                "",
            ])

            for f in group:
                lines.extend([
                    f"#### [{f.id}] {f.title}",
                    "",
                    f"- **Módulo:** `{f.module}`",
                    f"- **URL afectada:** {f.url or result.target.url}",
                    f"- **Descripción:** {f.description}",
                    f"- **Impacto:** {f.impact}",
                    f"- **Evidencia:**",
                    "```text",
                    f"{f.evidence}",
                    "```",
                    f"- **Recomendación paso a paso:** {f.recommendation}",
                    f"- **Referencia técnica:** [{f.reference}]({f.reference})",
                    "",
                ])

        lines.extend([
            "---",
            "*Generado éticamente con [WebSec Auditor](https://github.com/websec/websec-auditor). Herramienta de auditoría autorizada.*",
            "",
        ])

        output_path.write_text("\n".join(lines), encoding="utf-8")
