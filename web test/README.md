# 🛡️ WebSec Auditor

**WebSec Auditor** es una herramienta profesional de línea de comandos en Python (3.11+) diseñada para auditar la seguridad de aplicaciones y sitios web de forma **ética, autorizada y no destructiva**.

Proporciona análisis en profundidad (tanto pasivos como activos de baja intensidad) y genera reportes integrales con puntuación (0-100), calificación (A+ a F), y archivos dedicados para la remediación de vulnerabilidades.

---

## ⚠️ Reglas Éticas Obligatorias

1. **Autorización Estricta:** Esta herramienta solo debe ejecutarse sobre sitios web propios o con autorización escrita previa del propietario legal.
2. **Pruebas No Destructivas:** Las pruebas activas únicamente envían marcadores canarios inocuos de detección (ej. para verificar reflejo de parámetros o errores de sintaxis). **Bajo ninguna circunstancia se intenta explotar fallos, extraer datos o alterar sistemas**.
3. **Restricción de Alcance:** El escaneo nunca sale del dominio y subdominios explícitamente autorizados.
4. **Protección de Disponibilidad:** Se aplica un límite de tasa por defecto (2 peticiones/segundo) con un User-Agent identificable (`WebSecAuditor/1.0`).

---

## 🚀 Instalación

Requisitos: **Python 3.11+**

```bash
# 1. Clonar o acceder a la carpeta del proyecto
cd "web test"

# 2. Instalar el paquete en modo editable con herramientas de desarrollo
pip install -e ".[dev]"
```

Para verificar que la instalación fue exitosa:
```bash
websec --version
```

---

## 💻 Ejemplos de Uso

### 1. Escaneo Completo con Confirmación de Autorización
```bash
websec scan https://mi-sitio.com --i-have-permission
```
*(Si no se incluye `--i-have-permission`, la herramienta solicitará confirmación explícita e interactiva antes de comenzar).*

### 2. Escaneo de Módulos Específicos
```bash
websec scan https://mi-sitio.com --i-have-permission --modules headers,tls,xss,sqli,cors
```

### 3. Ajuste de Profundidad, Rate Limit y Formatos
```bash
websec scan https://mi-sitio.com --i-have-permission --depth 2 --rate-limit 1.0 --format console,json,html,md
```

### 4. Listar Módulos Disponibles
```bash
websec list-modules
```

### 5. Actualizar Base de Datos Local de CVEs
```bash
websec update-db
```

---

## 🔍 Catálogo de Módulos

WebSec Auditor cuenta con **17 módulos** especializados:

### Módulos Pasivos (Solo Observación)
1. **`headers`**: Audita CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy y fuga en Server/X-Powered-By.
2. **`tls`**: Valida redirección HTTP->HTTPS, expiración del certificado y versiones TLS.
3. **`cookies`**: Inspecciona flags `Secure`, `HttpOnly` y `SameSite` en cookies de sesión.
4. **`mixed_content`**: Detecta recursos HTTP en páginas HTTPS y valida Subresource Integrity (SRI) en scripts de terceros.
5. **`tech_fingerprint`**: Detecta CMS, frameworks y librerías contrastando versiones con la base local de CVEs (`vulnerable_libs.json`).
6. **`dns_email`**: Comprueba registros de seguridad DNS: SPF, DMARC y CAA.
7. **`error_pages`**: Detecta mensajes de error que exponen trazas de depuración (stack traces) o rutas locales de archivos.

### Módulos Activos (Detección No Destructiva)
8. **`xss`**: Inyección de marcadores canarios aleatorios inocuos (`wsa_xss_<id>`) para comprobar reflejo sin codificación HTML.
9. **`sqli`**: Envío de comilla simple para identificar firmas de error de sintaxis en bases de datos (MySQL, Postgres, SQLite, MSSQL, Oracle).
10. **`open_redirect`**: Prueba de parámetros de redirección (`?url=`, `?next=`) con URL de control externa segura.
11. **`cors`**: Detección de reflejo de orígenes arbitrarios o `null` con credenciales habilitadas.
12. **`clickjacking`**: Evaluación de resistencia al enmarcado en `<iframe>`.
13. **`csrf`**: Detección de formularios sensibles (POST/PUT/DELETE) desprovistos de tokens anti-CSRF.
14. **`exposed_files`**: Verificación de presencia de `/.git/HEAD`, `/.env`, `/backup.zip`, `/robots.txt`, `/sitemap.xml`, etc.
15. **`content_discovery`**: Mapeo controlado de rutas comunes no indexadas mediante una wordlist pequeña integrada.
16. **`subdomains`**: Enumeración pasiva de subdominios vía Certificate Transparency (crt.sh) y verificación DNS.
17. **`http_methods`**: Consulta vía `OPTIONS` para detectar métodos peligrosos habilitados (TRACE, PUT, DELETE).

---

## 📊 Interpretación de Reportes

Al finalizar cada análisis, los reportes se organizan automáticamente en la carpeta:
`reports/<dominio>-<timestamp>/`

### 1. Archivo `vulnerabilities.json`
Contiene la lista limpia y normalizada de todos los hallazgos en formato JSON. Es ideal para:
- Automatización en pipelines de CI/CD.
- Ingesta en SIEM o sistemas de gestión de vulnerabilidades (DefectDojo, etc.).

### 2. Archivo `VULNERABILITIES.md`
Genera un resumen en Markdown estructurado y agrupado por severidad (**Crítica**, **Alta**, **Media**, **Baja**, **Informativa**).
- Pensado para copiar y pegar directamente como issue en GitHub o como ticket en Jira.
- Cada hallazgo detalla: impacto, evidencia exacta, recomendación de corrección paso a paso y referencias oficiales (OWASP, CWE, MDN).

### 3. Reporte HTML Interactivo (`report.html`)
Un dashboard autocontenido y visual con:
- Gráfico/tarjetas de severidad y cálculo de puntuación global (0-100) y calificación (A+ a F).
- Filtros dinámicos por nivel de severidad.
- Botón para imprimir o exportar a PDF en formato limpio.

---

## 🧪 Laboratorio de Pruebas Local (`lab/`)

Para experimentar con todas las capacidades de detección de WebSec Auditor sin tocar ningún servidor real:

```bash
# Iniciar servidor Flask intencionalmente vulnerable
python lab/app.py

# En otra terminal, ejecutar la auditoría:
websec scan http://127.0.0.1:5000 --i-have-permission
```

---

## 🛠️ Cómo Agregar un Nuevo Módulo

1. Crea tu módulo en `src/websec/modules/passive/` o `src/websec/modules/active/` heredando de `BaseModule`.
2. Implementa el método `run(target, client, crawled_pages, config) -> list[Finding]`.
3. Registra tu clase en `src/websec/modules/__init__.py`.
4. Añade pruebas unitarias con mocks (`respx`) en `tests/test_<nombre>.py`.
5. Ejecuta `pytest` para validar cobertura y ausencia de regresiones.

---

## 📜 Licencia

Distribuido bajo la Licencia **MIT**. Consulta [`LICENSE`](LICENSE) para más información.
