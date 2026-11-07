# Arquitectura de WebSec Auditor

WebSec Auditor está construido bajo una arquitectura modular desacoplada en capas, diseñada para facilitar la extensibilidad y garantizar operaciones seguras y no destructivas.

```
                    ┌─────────────────────────┐
                    │        CLI / API        │
                    │   (Typer / Scripts)     │
                    └────────────┬────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │    SecurityScanner      │
                    │      (Orquestador)      │
                    └──────┬────────────┬─────┘
                           │            │
            ┌──────────────▼─────┐  ┌───▼────────────────┐
            │   SafeHttpClient   │  │   LightCrawler     │
            │ (Rate limit/Scope) │  │ (Extract Links/Forms│
            └──────────────┬─────┘  └───┬────────────────┘
                           │            │
            ┌──────────────┴────────────┴─────┐
            │          Módulos Base           │
            ├──────────────────┬──────────────┤
            │ Pasivos (7)      │ Activos (10) │
            │ - Headers        │ - XSS        │
            │ - TLS            │ - SQLi       │
            │ - Cookies        │ - Open Redir │
            │ - Mixed Content  │ - CORS       │
            │ - Fingerprint    │ - Clickjack  │
            │ - DNS/Email      │ - CSRF       │
            │ - Error Pages    │ - Exposed    │
            │                  │ - Discovery  │
            │                  │ - Subdomains │
            │                  │ - Methods    │
            └──────────────────┬──────────────┘
                               │
                    ┌──────────▼──────────────┐
                    │    SecurityScorer       │
                    │   (0-100 & Grade A-F)   │
                    └──────────┬──────────────┘
                               │
            ┌──────────────────▼──────────────────────┐
            │         Generadores de Reportes         │
            │  - Console (Rich)                       │
            │  - vulnerabilities.json & .md           │
            │  - report.html (Jinja2 interactivo)     │
            │  - report.json                          │
            └─────────────────────────────────────────┘
```

## Principios de Diseño
1. **Delimitación Estricta de Alcance (`Target.in_scope`):** Ninguna petición sale del dominio o subdominios autorizados.
2. **Pacing y Limitación de Frecuencia (`SafeHttpClient`):** Control de velocidad estricto por defecto a 2 req/s para prevenir denegación accidental de servicio.
3. **Pruebas No Destructivas:** Los módulos activos solo envían marcadores canarios de comprobación de reflejo o errores de sintaxis; nunca se ejecutan payloads de explotación real.
4. **Desacoplamiento de Módulos:** Cada módulo hereda de `BaseModule` y produce objetos `Finding` homogéneos e inmutables.
