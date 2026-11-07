"""Cálculo de puntaje global (0-100) y calificación A-F de seguridad."""

from typing import List
from websec.core.models import Finding, ScoreResult, Severity


class SecurityScorer:
    """Calculador de puntuación de seguridad y evaluación general."""

    @staticmethod
    def calculate(findings: List[Finding]) -> ScoreResult:
        """Calcula el puntaje de 0 a 100 y la calificación A-F."""
        base_score = 100
        breakdown = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0,
        }

        total_penalty = 0
        for f in findings:
            breakdown[f.severity.value] += 1
            total_penalty += f.severity.score_penalty

        final_score = max(0, base_score - total_penalty)

        # Asignación de calificación
        if final_score >= 95:
            grade = "A+"
        elif final_score >= 85:
            grade = "A"
        elif final_score >= 75:
            grade = "B"
        elif final_score >= 60:
            grade = "C"
        elif final_score >= 45:
            grade = "D"
        else:
            grade = "F"

        # Resumen cualitativo
        if grade in ("A+", "A"):
            summary = "Excelente postura de seguridad. Se observan buenas prácticas generales."
        elif grade == "B":
            summary = "Buena postura de seguridad, aunque con áreas de mejora en configuración."
        elif grade == "C":
            summary = "Postura moderada. Existen debilidades que aumentan la superficie de riesgo."
        elif grade == "D":
            summary = "Postura deficiente. Se detectaron vulnerabilidades que requieren atención urgente."
        else:
            summary = "Postura crítica. Riesgo elevado con fallos graves de seguridad y exposición."

        return ScoreResult(
            score=final_score,
            grade=grade,
            breakdown=breakdown,
            summary=summary,
        )
