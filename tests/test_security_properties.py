"""Propiedades de seguridad más fuertes que "no lanza excepción".

Cada prueba afirma un invariante sobre todo el dominio de entrada: alcance (scope),
esquemas peligrosos, determinismo del score y reflejo de canarios XSS.
"""

from urllib.parse import urlparse

from bs4 import BeautifulSoup
from hypothesis import given, settings, strategies as st

from websec.config import ScanConfig
from websec.core.crawler import LightCrawler
from websec.core.models import Finding, Severity, Target
from websec.core.scoring import SecurityScorer

LABEL = st.from_regex(r"[a-z0-9]([a-z0-9\-]{0,10}[a-z0-9])?", fullmatch=True)
DOMAIN = st.builds(lambda a, tld: f"{a}.{tld}", LABEL, st.sampled_from(["com", "org", "net", "es"]))
DANGEROUS_SCHEMES = ["javascript", "vbscript", "data", "file", "ftp", "mailto", "tel"]


def _random_case(draw, text: str) -> str:
    flips = draw(st.lists(st.booleans(), min_size=len(text), max_size=len(text)))
    return "".join(c.upper() if f else c for c, f in zip(text, flips))


# ---------------------------------------------------------------------------
# Alcance: dominios parecidos nunca entran en scope
# ---------------------------------------------------------------------------

@given(domain=DOMAIN, evil=DOMAIN, allow_subdomains=st.booleans())
def test_property_lookalike_domains_never_in_scope(domain, evil, allow_subdomains):
    """Sufijos, prefijos y credenciales embebidas no engañan al control de alcance."""
    target = Target(f"https://{domain}")
    lookalikes = [
        f"https://{domain}.{evil}/",       # target.com.evil.com
        f"https://x{domain}/",             # xtarget.com
        f"https://{domain}@{evil}/",       # credenciales falsas: el host real es evil
        f"//{domain}.{evil}/path",         # relativa a esquema
    ]
    for url in lookalikes:
        host = urlparse(url).hostname or ""
        if host == domain or host.endswith(f".{domain}"):
            continue  # p.ej. evil == domain: es un subdominio legítimo, no un parecido
        assert target.in_scope(url, allow_subdomains) is False, url


@given(domain=DOMAIN, path=st.from_regex(r"(/[a-z0-9]{0,8}){0,3}", fullmatch=True), data=st.data())
def test_property_scope_is_host_case_insensitive(domain, path, data):
    """Cambiar mayúsculas del host no altera la decisión de alcance."""
    target = Target(f"https://{domain}")
    variant = _random_case(data.draw, domain)
    assert target.in_scope(f"https://{variant}{path}") is True


@given(domain=DOMAIN, scheme=st.sampled_from(DANGEROUS_SCHEMES), data=st.data(),
       rest=st.text(alphabet="abc/:().'", max_size=20))
def test_property_dangerous_schemes_never_in_scope(domain, scheme, data, rest):
    """Ningún esquema no-HTTP entra en scope, sin importar mayúsculas."""
    target = Target(f"https://{domain}")
    url = f"{_random_case(data.draw, scheme)}:{rest}"
    assert target.in_scope(url, allow_subdomains=True) is False


# ---------------------------------------------------------------------------
# Crawler: todo enlace extraído es http(s)
# ---------------------------------------------------------------------------

HREF = st.one_of(
    st.from_regex(r"/[a-z0-9/]{0,12}", fullmatch=True),
    st.builds(lambda s, r: f"{s}:{r}", st.sampled_from(DANGEROUS_SCHEMES + ["JavaScript", "JAVASCRIPT", "VbScript"]),
              st.text(alphabet="abc()1", max_size=10)),
    st.builds(lambda d: f"https://{d}/", DOMAIN),
    st.just("#top"),
)


@given(hrefs=st.lists(HREF, max_size=8), leading_ws=st.sampled_from(["", " ", "\t", "\n "]))
@settings(max_examples=150)
def test_property_crawler_only_extracts_http_links(hrefs, leading_ws):
    """El crawler jamás devuelve enlaces con esquemas ejecutables o no-HTTP."""
    target = Target("https://site.test")
    crawler = LightCrawler(target, None, ScanConfig(target_url=target.url, has_permission=True))  # type: ignore[arg-type]
    html = "".join(f'<a href="{leading_ws}{h}">x</a>' for h in hrefs)
    links = crawler._extract_links(BeautifulSoup(html, "html.parser"), target.url)
    for link in links:
        assert urlparse(link).scheme in ("http", "https"), link


# ---------------------------------------------------------------------------
# Scoring: invariante a permutaciones y grado coherente con el puntaje
# ---------------------------------------------------------------------------

def _finding(sev: Severity) -> Finding:
    return Finding(id="P", title="t", module="m", severity=sev, description="d",
                   evidence="e", impact="i", recommendation="r", reference="https://owasp.org")


SEVS = st.lists(st.sampled_from(list(Severity)), max_size=30)


@given(sevs=SEVS, data=st.data())
def test_property_score_ignores_finding_order(sevs, data):
    """El orden en que los módulos reportan hallazgos no altera el resultado."""
    shuffled = data.draw(st.permutations(sevs))
    a = SecurityScorer.calculate([_finding(s) for s in sevs])
    b = SecurityScorer.calculate([_finding(s) for s in shuffled])
    assert (a.score, a.grade, a.breakdown) == (b.score, b.grade, b.breakdown)


@given(sevs=SEVS)
def test_property_info_findings_never_change_score(sevs):
    """Hallazgos informativos son el elemento neutro del puntaje."""
    base = SecurityScorer.calculate([_finding(s) for s in sevs])
    plus_info = SecurityScorer.calculate([_finding(s) for s in sevs] + [_finding(Severity.INFO)] * 5)
    assert (plus_info.score, plus_info.grade) == (base.score, base.grade)


GRADE_ORDER = ["F", "D", "C", "B", "A", "A+"]


@given(a=SEVS, b=SEVS)
def test_property_grade_is_monotonic_in_score(a, b):
    """Mayor puntaje nunca implica peor calificación."""
    ra = SecurityScorer.calculate([_finding(s) for s in a])
    rb = SecurityScorer.calculate([_finding(s) for s in b])
    if ra.score >= rb.score:
        assert GRADE_ORDER.index(ra.grade) >= GRADE_ORDER.index(rb.grade)
