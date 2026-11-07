# Laboratorio de Pruebas Vulnerable (WebSec Lab)

Este entorno es un servidor local intencionalmente vulnerable desarrollado con Flask. Su objetivo es proporcionar un campo de entrenamiento ético y seguro para validar todas las capacidades de **WebSec Auditor** sin interactuar con ningún servidor en internet.

## Instrucciones de Inicio

1. Instalar dependencias del laboratorio:
   ```bash
   pip install -r lab/requirements.txt
   ```

2. Iniciar el servidor local:
   ```bash
   python lab/app.py
   ```
   El servidor responderá en `http://127.0.0.1:5000`.

3. Ejecutar una auditoría de prueba:
   ```bash
   websec scan http://127.0.0.1:5000 --i-have-permission
   ```
