# Guía de Contribución a WebSec Auditor

Agradecemos enormemente las contribuciones de la comunidad. Para mantener los más altos estándares de calidad y ética, por favor siga estas directrices:

## Cómo Agregar un Nuevo Módulo de Análisis
1. Decida si el módulo es **pasivo** (solo analiza respuestas ya obtenidas) o **activo** (envía una sonda inocua de detección).
2. Cree un nuevo archivo en `src/websec/modules/passive/` o `src/websec/modules/active/`.
3. Heredar de `BaseModule` e implementar el método `run()`:
   ```python
   from websec.modules.base import BaseModule
   from websec.core.models import Finding, Severity, Target
   from websec.core.http_client import SafeHttpClient
   from websec.core.crawler import CrawledPage
   from websec.config import ScanConfig

   class NuevoModulo(BaseModule):
       name = "nuevo_modulo"
       description = "Descripción concisa del análisis"
       category = "passive"  # o "active"

       def run(self, target: Target, client: SafeHttpClient, crawled_pages: list[CrawledPage], config: ScanConfig) -> list[Finding]:
           findings = []
           # Lógica de detección no destructiva...
           return findings
   ```
4. Registrar el nuevo módulo en `src/websec/modules/__init__.py`.
5. Crear la suite de pruebas unitarias correspondiente en `tests/test_nuevo_modulo.py` utilizando `respx` o mocks sin realizar peticiones reales a la red.
6. Ejecutar `pytest` y verificar que la cobertura supere el 80%.

## Estilo de Código y Pruebas
- Formatear con `black` y revisar con `ruff`.
- Verificar tipado estático con `mypy`.
- Asegurarse de que ningún test realice peticiones reales a internet.
