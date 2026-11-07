"""Servidor vulnerable de laboratorio local para prácticas y validación de WebSec Auditor."""

from flask import Flask, Response, make_response, redirect, render_template_string, request

app = Flask(__name__)

INDEX_HTML = """
<!DOCTYPE html>
<html>
<head><title>WebSec Lab Vulnerable</title></head>
<body>
  <h1>Bienvenido al Laboratorio Vulnerable de WebSec</h1>
  <p>Esta aplicación contiene fallos de seguridad comunes para verificar el funcionamiento del auditor.</p>
  <ul>
    <li><a href="/search?q=test">Búsqueda (Reflected XSS)</a></li>
    <li><a href="/product?id=1">Producto (SQLi Error Heuristic)</a></li>
    <li><a href="/redirect?url=/login">Redirección (Open Redirect)</a></li>
    <li><a href="/api/user">API (CORS Inseguro)</a></li>
    <li><a href="/login">Login (Cookies sin HttpOnly/Secure)</a></li>
    <li><a href="/settings">Ajustes (Formulario sin CSRF)</a></li>
    <li><a href="/debug-error">Error con Stack Trace</a></li>
  </ul>
</body>
</html>
"""

@app.route("/")
def index():
    resp = make_response(INDEX_HTML)
    resp.headers["Server"] = "Apache/2.4.41 (Ubuntu)"
    resp.headers["X-Powered-By"] = "PHP/7.4.3"
    return resp

@app.route("/search")
def search():
    q = request.args.get("q", "")
    # Vulnerabilidad: Reflejo directo sin escapar HTML
    html = f"<html><body><h1>Resultados para: {q}</h1><a href='/'>Volver</a></body></html>"
    return Response(html, mimetype="text/html")

@app.route("/product")
def product():
    product_id = request.args.get("id", "")
    if "'" in product_id:
        # Vulnerabilidad: Fuga de error de sintaxis SQL
        return Response("Fatal error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version", status=500)
    return Response(f"Detalles del producto #{product_id}", mimetype="text/html")

@app.route("/redirect")
def open_redirect():
    target = request.args.get("url", "/")
    # Vulnerabilidad: Redirección sin validación de dominio
    return redirect(target, code=302)

@app.route("/api/user")
def api_user():
    origin = request.headers.get("Origin", "")
    resp = make_response('{"id": 1, "username": "admin", "role": "root"}')
    # Vulnerabilidad: Reflejo arbitrario de Origin con credenciales
    if origin:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    return resp

@app.route("/login")
def login():
    html = """
    <html><body>
      <h2>Iniciar Sesión</h2>
      <form action="/login" method="POST">
        Usuario: <input type="text" name="username"><br>
        Clave: <input type="password" name="password"><br>
        <button type="submit">Entrar</button>
      </form>
    </body></html>
    """
    resp = make_response(html)
    # Vulnerabilidad: Cookie de sesión sin Secure ni HttpOnly
    resp.set_cookie("session_id", "secret_session_token_12345", samesite=None)
    return resp

@app.route("/settings")
def settings():
    # Vulnerabilidad: Formulario POST sin token CSRF
    html = """
    <html><body>
      <h2>Cambiar Correo</h2>
      <form action="/change-email" method="POST">
        Nuevo Correo: <input type="email" name="email">
        <button type="submit">Actualizar</button>
      </form>
    </body></html>
    """
    return html

@app.route("/.git/HEAD")
def git_head():
    return Response("ref: refs/heads/main\n", mimetype="text/plain")

@app.route("/.env")
def env_file():
    return Response("DB_PASSWORD=SuperSecretPass123!\nAPP_KEY=base64:xyz\n", mimetype="text/plain")

@app.route("/debug-error")
def debug_error():
    # Vulnerabilidad: Trazas de depuración expuestas
    trace = """
    Traceback (most recent call last):
      File "/app/websec_lab/app.py", line 85, in trigger_bug
        raise ValueError("Simulated internal server error with debug trace")
    ValueError: Simulated internal server error with debug trace
    """
    return Response(trace, status=500, mimetype="text/plain")

if __name__ == "__main__":
    print("[*] Iniciando laboratorio vulnerable en http://127.0.0.1:5000 ...")
    app.run(host="127.0.0.1", port=5000, debug=False)
