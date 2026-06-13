from __future__ import annotations

from opswitness.core.events import Finding, RunGraph


class GraphExplainer:
    def explain_finding(self, graph: RunGraph, finding: Finding) -> str:
        nodes_by_id = {node.id: node for node in graph.nodes}
        path_labels = [
            f"{nodes_by_id[node_id].type}:{nodes_by_id[node_id].label}"
            for node_id in finding.path
            if node_id in nodes_by_id
        ]
        evidence = "; ".join(path_labels) if path_labels else "No graph path was attached."
        return (
            f"{finding.title}. {finding.summary} Evidence path: {evidence}. "
            f"Recommended action: {finding.recommendation}"
        )

