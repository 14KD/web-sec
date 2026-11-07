---
name: graph-audit-test
description: Ejecuta la batería de pruebas drásticas (Fuzzing, Chaos, E2E Lab y Validación por Grafo) y actualiza el grafo de conocimiento.
---

# Workflow: Auditoría y Pruebas Drásticas Guiadas por Grafo

Este workflow ejecuta la batería completa de validación del proyecto WebSec Auditor:

1. **Ejecución de Pruebas Multi-Capa**:
   - `pytest tests/test_fuzz_properties.py` (Hypothesis: invariantes matemáticos y resiliencia de parsing)
   - `pytest tests/test_chaos_resilience.py` (Inyección de fallos de red: timeouts, bucles 302, caídas 500)
   - `pytest tests/test_e2e_lab.py` (Integración real contra el laboratorio vulnerable local)
   - `pytest tests/test_graph_driven.py` (Validación de límites arquitectónicos en graph.json)

2. **Sincronización del Grafo**:
   - `graphify update "web test"` para reflejar los cambios en el AST sin consumo de API.
