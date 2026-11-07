"""Pruebas drásticas basadas en propiedades (Property-Based Testing) y fuzzing con Hypothesis.

Verifica formalmente invariantes matemáticos y de seguridad del escáner frente a
miles de entradas adversarias generadas aleatoriamente.
"""

import json
from hypothesis import given, strategies as st, settings, HealthCheck
from bs4 import BeautifulSoup

from websec.core.models import Finding, Severity, Target
from websec.core.scoring import SecurityScorer
from websec.core.crawler import LightCrawler, CrawledPage
from websec.config import ScanConfig


# ---------------------------------------------------------------------------
# Invariante 1: SecurityScorer es monótono, acotado en [0, 100] y determinista
# ---------------------------------------------------------------------------

@st.composite
def findings_list(draw):
    """Generador arbitrario de listas de hallazgos de seguridad."""
    severities = draw(st.lists(st.sampled_from(list(Severity)), max_size=50))
    findings = []
    for i, sev in enumerate(severities):
        findings.append(
            Finding(
                id=f"WSA-TEST-{i:03d}",
                title=f"Vulnerabilidad generada {i}",
                module="fuzz_module",
                severity=sev,
                description="Descripción de prueba para fuzzing.",
                evidence="Evidencia generada automáticamente.",
                impact="Impacto adverso simulado.",
                recommendation="Aplicar parches inmediatos.",
                reference="https://owasp.org",
            )
        )
    return findings


@given(findings=findings_list())
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property_scorer_invariants(findings):
    """El score resultante SIEMPRE debe ser un entero entre 0 y 100 y tener grado válido."""
    result = SecurityScorer.calculate(findings)

    # 1. Rango acotado
    assert 0 <= result.score <= 100
    assert isinstance(result.score, int)

    # 2. Grado válido
    assert result.grade in ("A+", "A", "B", "C", "D", "F")

    # 3. Suma del breakdown idéntica al total de hallazgos
    total_breakdown = sum(result.breakdown.values())
    assert total_breakdown == len(findings)

    # 4. Resumen no vacío
    assert len(result.summary) > 0


@given(f1=findings_list(), f2=findings_list())
@settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
def test_property_scorer_monotonicity(f1, f2):
    """Añadir más vulnerabilidades nunca puede aumentar la puntuación de seguridad."""
    combined = f1 + f2
    score_f1 = SecurityScorer.calculate(f1).score
    score_combined = SecurityScorer.calculate(combined).score

    assert score_combined <= score_f1


# ---------------------------------------------------------------------------
# Invariante 2: Target.in_scope es seguro frente a cualquier entrada arbitraria
# ---------------------------------------------------------------------------

@given(
    base_domain=st.from_regex(r"[a-z0-9\-]{1,20}\.(com|org|net|es)", fullmatch=True),
    random_input=st.text(max_size=200),
    allow_subdomains=st.booleans(),
)
@settings(max_examples=100)
def test_property_target_in_scope_adversarial(base_domain, random_input, allow_subdomains):
    """Target.in_scope nunca lanza excepciones no controladas y rechaza esquemas peligrosos."""
    target = Target(f"https://{base_domain}")

    # Jamás debe lanzar excepción no controlada
    in_scope = target.in_scope(random_input, allow_subdomains=allow_subdomains)
    assert isinstance(in_scope, bool)

    # Esquemas no-HTTP jamás deben estar en scope
    lower_input = random_input.lower().strip()
    if lower_input.startswith(("javascript:", "mailto:", "data:", "file:", "ftp:", "tel:")):
        assert in_scope is False


@given(
    domain=st.from_regex(r"[a-z0-9\-]{3,15}\.example\.org", fullmatch=True),
    subdomain_label=st.from_regex(r"[a-z0-9\-]{1,10}", fullmatch=True),
)
@settings(max_examples=50)
def test_property_target_subdomain_scope_control(domain, subdomain_label):
    """Subdominios sólo son admitidos si allow_subdomains=True."""
    target = Target(f"https://{domain}")
    subdomain_url = f"https://{subdomain_label}.{domain}/dashboard"

    assert target.in_scope(subdomain_url, allow_subdomains=False) is False
    assert target.in_scope(subdomain_url, allow_subdomains=True) is True


# ---------------------------------------------------------------------------
# Invariante 3: Finding.to_dict es siempre serializable a JSON estándar
# ---------------------------------------------------------------------------

@given(
    title=st.text(max_size=100),
    desc=st.text(max_size=200),
    ev=st.text(max_size=200),
    url_candidate=st.one_of(st.none(), st.text(max_size=100)),
    sev=st.sampled_from(list(Severity)),
)
@settings(max_examples=80)
def test_property_finding_json_serialization(title, desc, ev, url_candidate, sev):
    """Cualquier Finding con contenido arbitrario o unicode se serializa a JSON sin fallo."""
    finding = Finding(
        id="WSA-FUZZ-001",
        title=title,
        module="fuzz",
        severity=sev,
        description=desc,
        evidence=ev,
        impact="Impacto",
        recommendation="Mitigación",
        reference="https://example.com",
        url=url_candidate,
    )

    data = finding.to_dict()
    assert isinstance(data, dict)

    # Debe ser 100% serializable a JSON RFC 8259
    json_string = json.dumps(data)
    assert isinstance(json_string, str)
    deserialized = json.loads(json_string)
    assert deserialized["title"] == title
    assert deserialized["severity"] == sev.value


# ---------------------------------------------------------------------------
# Invariante 4: LightCrawler parsing no colapsa frente a HTML corrupto/malicioso
# ---------------------------------------------------------------------------

@given(corrupt_html=st.text(max_size=1000))
@settings(max_examples=80)
def test_property_crawler_html_parsing_resilience(corrupt_html):
    """Los métodos de extracción del crawler toleran cualquier HTML malformado o binario."""
    target = Target("https://fuzz-target.test")
    config = ScanConfig(target_url=target.url, has_permission=True)
    # Instanciamos crawler pasando None como cliente ya que sólo probamos extracción
    crawler = LightCrawler(target, None, config)  # type: ignore

    soup = BeautifulSoup(corrupt_html, "html.parser")

    links = crawler._extract_links(soup, target.url)
    assert isinstance(links, list)

    forms = crawler._extract_forms(soup, target.url)
    assert isinstance(forms, list)
    for form in forms:
        assert isinstance(form.action, str)
        assert isinstance(form.inputs, list)

    scripts = crawler._extract_resources(soup, target.url, "script", "src")
    assert isinstance(scripts, list)
