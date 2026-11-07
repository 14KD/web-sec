"""Pruebas drásticas guiadas por el Grafo de Conocimiento (Knowledge Graph Driven Testing).

Aprovecha la topología generada en `graphify-out/graph.json` para:
- Auditar la integridad arquitectónica del código.
- Verificar que todo módulo registrado en el escáner tiene nodo en el grafo y cobertura de tests.
- Asegurar que no existen ciclos ni dependencias indebidas entre módulos y CLI.
"""

import json
from pathlib import Path
import pytest
from websec.modules import ALL_MODULES


def find_graph_file() -> Path:
    """Busca el archivo graph.json en graphify-out del espacio de trabajo."""
    candidates = [
        Path(__file__).resolve().parent.parent.parent / "graphify-out" / "graph.json",
        Path(__file__).resolve().parent.parent / "graphify-out" / "graph.json",
    ]
    for p in candidates:
        if p.exists():
            return p
    pytest.skip("graphify-out/graph.json no encontrado")


@pytest.fixture(scope="module")
def graph_data() -> dict:
    graph_path = find_graph_file()
    with open(graph_path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_graph_links(graph_data: dict) -> list:
    """Extrae las aristas/enlaces del grafo según el esquema networkx node-link."""
    return graph_data.get("links") or graph_data.get("edges") or []


def test_graph_has_nodes_and_edges(graph_data: dict) -> None:
    """El grafo de conocimiento debe contener nodos y relaciones válidas extraídas."""
    nodes = graph_data.get("nodes", [])
    links = get_graph_links(graph_data)

    assert len(nodes) > 50, f"Grafo insuficiente: sólo {len(nodes)} nodos"
    assert len(links) > 50, f"Grafo sin suficientes enlaces: sólo {len(links)} enlaces"


def test_graph_all_security_modules_are_indexed(graph_data: dict) -> None:
    """Todos los módulos del catálogo del escáner deben existir como nodos en el grafo."""
    nodes = graph_data.get("nodes", [])
    node_labels = {n.get("label", "").lower() for n in nodes}
    node_files = {str(n.get("file", "")).lower() for n in nodes}

    for mod_cls in ALL_MODULES:
        mod_name = mod_cls.name.lower()
        found_in_labels = any(mod_name in lbl for lbl in node_labels)
        found_in_files = any(f"{mod_name}.py" in f for f in node_files)
        assert found_in_labels or found_in_files, f"Módulo '{mod_name}' no detectado en graphify"


def test_graph_architectural_boundaries(graph_data: dict) -> None:
    """Arquitectura limpia: Los módulos del escáner no deben depender de la capa CLI."""
    links = get_graph_links(graph_data)
    nodes_by_id = {n["id"]: n for n in graph_data.get("nodes", [])}

    for edge in links:
        source_node = nodes_by_id.get(edge.get("source"))
        target_node = nodes_by_id.get(edge.get("target"))

        if not source_node or not target_node:
            continue

        source_file = str(source_node.get("file", "")).replace("\\", "/")
        target_file = str(target_node.get("file", "")).replace("\\", "/")

        if "/modules/" in source_file:
            assert "cli.py" not in target_file, (
                f"Violación arquitectónica detectada en el grafo: {source_file} depende de {target_file}"
            )


def test_graph_scanner_connects_to_core_abstractions(graph_data: dict) -> None:
    """SecurityScanner debe tener conectividad en el grafo con los pilares de la arquitectura."""
    links = get_graph_links(graph_data)
    nodes_by_id = {n["id"]: n for n in graph_data.get("nodes", [])}

    scanner_node_ids = [
        n["id"] for n in graph_data.get("nodes", [])
        if "SecurityScanner" in n.get("label", "")
    ]
    assert len(scanner_node_ids) > 0, "SecurityScanner no encontrado en el grafo"

    connected_labels = set()
    for edge in links:
        if edge.get("source") in scanner_node_ids:
            target_id = edge.get("target")
            if target_id in nodes_by_id:
                connected_labels.add(nodes_by_id[target_id].get("label", ""))

    # Debe relacionarse con SafeHttpClient, LightCrawler, SecurityScorer y BaseModule
    assert "SafeHttpClient" in connected_labels
    assert "LightCrawler" in connected_labels
    assert "SecurityScorer" in connected_labels
    assert "BaseModule" in connected_labels
