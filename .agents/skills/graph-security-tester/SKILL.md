---
name: graph-security-tester
description: Agente especializado en auditoría y testing de seguridad web guiado por grafos de conocimiento. Utiliza graphify para mapear la topología del código, analizar superficies de ataque y coordinar tests basados en propiedades, inyecciones de caos y validaciones E2E.
---

# Graph Security Tester Skill

Esta skill capacita al agente para realizar pruebas avanzadas de seguridad y calidad arquitectónica utilizando el grafo de conocimiento del proyecto (`graphify`).

## Capacidades Principales

1. **Exploración Topológica con Graphify**:
   - Consultar la arquitectura del escáner con `graphify query "<pregunta>"`.
   - Rastrear el flujo de datos y dependencias entre módulos usando `graphify path "<Origen>" "<Destino>"`.
   - Obtener detalles de una abstracción con `graphify explain "<Concepto>"`.

2. **Estrategia de Testeo Drástica Multi-Capa**:
   - **Pruebas Basadas en Propiedades (Hypothesis)**: Validación de invariantes matemáticos en `SecurityScorer`, control estricto de scope en `Target` y resiliencia de parsing en `LightCrawler`.
   - **Ingeniería de Caos (Fault Injection)**: Simulación de caídas de red, bucles de redirección 302, caídas con status 500 masivas y respuestas gigantes.
   - **Integración End-to-End Real**: Validación contra el laboratorio vulnerable (`lab/app.py`), comprobando la detección efectiva de las vulnerabilidades OWASP Top 10.
   - **Auditoría Arquitectónica por Grafo**: Asegura que ningún módulo de seguridad cree dependencias circulares o importe capas superiores (CLI/reportes).

## Flujo de Trabajo Recomendado para el Agente

### Paso 1: Mapear el Grafo
Antes de implementar un nuevo módulo o modificar uno existente:
```bash
graphify query "how is BaseModule implemented and registered in SecurityScanner"
```

### Paso 2: Ejecutar la Batería de Pruebas Drásticas
```bash
# Ejecutar suite completa con cobertura
pytest -v --cov=websec

# Ejecutar pruebas basadas en propiedades (Fuzzing)
pytest tests/test_fuzz_properties.py

# Ejecutar pruebas de caos y tolerancia a fallos
pytest tests/test_chaos_resilience.py

# Ejecutar integración E2E contra el laboratorio vulnerable en vivo
pytest tests/test_e2e_lab.py

# Ejecutar validaciones arquitectónicas guiadas por el grafo
pytest tests/test_graph_driven.py
```

### Paso 3: Mantener el Grafo Sincronizado
Tras modificar archivos de código, regenerar las extracciones sin costo de LLM:
```bash
graphify update .
```
