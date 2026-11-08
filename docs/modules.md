# Catálogo Detallado de Módulos

WebSec Auditor incluye 17 módulos de inspección clasificados en dos grandes categorías:

---

## 1. Módulos Pasivos (Solo Observación)

| Módulo | Clave CLI | Descripción Técnica |
| :--- | :--- | :--- |
| **Cabeceras HTTP** | `headers` | Valida CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, y fuga en Server/X-Powered-By. |
| **HTTPS / TLS** | `tls` | Verifica redirección HTTP->HTTPS, validez y fecha de expiración del certificado peer TLS. |
| **Cookies** | `cookies` | Inspecciona atributos `Secure`, `HttpOnly` y `SameSite` en todas las cookies emitidas. |
| **Contenido Mixto** | `mixed_content` | Detecta recursos HTTP (scripts, estilos, imágenes) en páginas HTTPS y valida Subresource Integrity (SRI) en scripts externos. |
| **Fingerprinting** | `tech_fingerprint` | Detecta CMS y librerías frontend/backend, comparando versiones contra la base local de CVEs conocidos. |
| **DNS y Correo** | `dns_email` | Valida registros SPF, DMARC (políticas de rechazo/cuarentena) y CAA mediante consultas DNS. |
| **Páginas de Error** | `error_pages` | Analiza respuestas 404/500 en busca de trazas de depuración (stack traces), consolas de depuración y rutas locales del servidor. |

---

## 2. Módulos Activos (Detección No Destructiva)

| Módulo | Clave CLI | Descripción Técnica |
| :--- | :--- | :--- |
| **XSS Reflejado** | `xss` | Inyecta marcadores canarios aleatorios inocuos (ej. `wsa_xss_<id>`) para detectar reflejo sin codificación HTML. |
| **SQLi Heurístico** | `sqli` | Envía una comilla simple `'` y busca firmas de error de sintaxis en el motor de base de datos (MySQL, Postgres, SQLite, Oracle, MSSQL). |
| **Open Redirect** | `open_redirect` | Inyecta una URL de control segura en parámetros típicos de redirección y valida si la cabecera `Location` apunta al destino externo. |
| **CORS Inseguro** | `cors` | Envía encabezados `Origin` externos y `null` para detectar reflejo permisivo y combinación indebida con credenciales. |
| **Clickjacking** | `clickjacking` | Evalúa si las páginas interactivas y formularios carecen de defensas contra incrustación en `<iframe>`. |
| **Falsificación CSRF**| `csrf` | Comprueba si formularios sensibles que alteran estado (POST, PUT, DELETE) carecen de token de sincronización anti-CSRF. |
| **Archivos Sensibles** | `exposed_files` | Comprueba con código de estado si rutas como `/.git/HEAD`, `/.env`, `robots.txt`, `security.txt` o copias de seguridad son accesibles. |
| **Descubrimiento** | `content_discovery` | Mapea rutas comunes no indexadas mediante una wordlist pequeña y controlada. |
| **Subdominios** | `subdomains` | Consulta los registros públicos de Certificate Transparency (crt.sh) y valida resolución DNS no intrusiva. |
| **Métodos HTTP** | `http_methods` | Envía peticiones `OPTIONS` para identificar métodos peligrosos habilitados (TRACE, PUT, DELETE). |
