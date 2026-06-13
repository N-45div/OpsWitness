from __future__ import annotations

import json
from pathlib import Path

from opswitness.core.events import GraphEdge, GraphNode, RunGraph


class JsonGraphStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, graph: RunGraph) -> Path:
        path = self.root / f"{graph.run_id}.graph.json"
        path.write_text(graph.model_dump_json(indent=2), encoding="utf-8")
        return path

    def load(self, run_id: str) -> RunGraph:
        path = self.root / f"{run_id}.graph.json"
        return RunGraph.model_validate_json(path.read_text(encoding="utf-8"))

    def list(self) -> list[RunGraph]:
        return [
            RunGraph.model_validate_json(path.read_text(encoding="utf-8"))
            for path in sorted(self.root.glob("*.graph.json"))
        ]


class KuzuGraphStore:
    """Embedded graph store.

    The app can run with JSON files alone, but this store gives the project a graph-native path.
    It is intentionally thin so the product remains easy to install.
    """

    def __init__(self, database_path: Path) -> None:
        import kuzu

        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = kuzu.Database(str(database_path))
        self.conn = kuzu.Connection(self.db)
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.execute(
            "CREATE NODE TABLE IF NOT EXISTS Node("
            "id STRING, run_id STRING, type STRING, label STRING, trust STRING, "
            "risk_tags STRING, data STRING, PRIMARY KEY(id))"
        )
        self.conn.execute(
            "CREATE REL TABLE IF NOT EXISTS Edge("
            "FROM Node TO Node, type STRING, label STRING, risk_tags STRING, data STRING)"
        )

    def save(self, graph: RunGraph) -> None:
        for node in graph.nodes:
            self._upsert_node(graph.run_id, node)
        for edge in graph.edges:
            self._insert_edge(edge)

    def _upsert_node(self, run_id: str, node: GraphNode) -> None:
        self.conn.execute(
            "MERGE (n:Node {id: $id}) "
            "SET n.run_id = $run_id, n.type = $type, n.label = $label, "
            "n.trust = $trust, n.risk_tags = $risk_tags, n.data = $data",
            {
                "id": node.id,
                "run_id": run_id,
                "type": node.type,
                "label": node.label,
                "trust": node.trust.value,
                "risk_tags": json.dumps(node.risk_tags),
                "data": json.dumps(node.data),
            },
        )

    def _insert_edge(self, edge: GraphEdge) -> None:
        self.conn.execute(
            "MATCH (a:Node {id: $source}), (b:Node {id: $target}) "
            "MERGE (a)-[e:Edge]->(b) "
            "SET e.type = $type, e.label = $label, e.risk_tags = $risk_tags, e.data = $data",
            {
                "source": edge.source,
                "target": edge.target,
                "type": edge.type,
                "label": edge.label,
                "risk_tags": json.dumps(edge.risk_tags),
                "data": json.dumps(edge.data),
            },
        )
