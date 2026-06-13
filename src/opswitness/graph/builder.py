from __future__ import annotations

from collections import defaultdict

from opswitness.core.events import AgentEvent, GraphEdge, GraphNode, RunGraph
from opswitness.core.labels import EDGE_BY_EVENT, NODE_TYPE_BY_EVENT, event_label
from opswitness.policy.engine import PolicyEngine


class GraphBuilder:
    def __init__(self, policy_engine: PolicyEngine | None = None) -> None:
        self.policy_engine = policy_engine or PolicyEngine()

    def build(self, events: list[AgentEvent]) -> list[RunGraph]:
        grouped: dict[str, list[AgentEvent]] = defaultdict(list)
        for event in events:
            grouped[event.run_id].append(event)

        graphs: list[RunGraph] = []
        for run_id, run_events in grouped.items():
            sorted_events = sorted(run_events, key=lambda item: item.timestamp)
            nodes = [self._node_from_event(event) for event in sorted_events]
            edges: list[GraphEdge] = []

            node_ids = {node.id for node in nodes}
            for event in sorted_events:
                if event.parent_node_id and event.parent_node_id in node_ids:
                    edge_type, label = EDGE_BY_EVENT.get(event.event_type, ("RELATED_TO", "related to"))
                    edges.append(
                        GraphEdge(
                            source=event.parent_node_id,
                            target=event.node_id,
                            type=edge_type,
                            label=label,
                            risk_tags=event.risk_tags,
                        )
                    )

            graph = RunGraph(run_id=run_id, nodes=nodes, edges=edges)
            graph.findings = self.policy_engine.evaluate(graph)
            graphs.append(graph)
        return graphs

    def _node_from_event(self, event: AgentEvent) -> GraphNode:
        return GraphNode(
            id=event.node_id,
            type=NODE_TYPE_BY_EVENT.get(event.event_type, "Event"),
            label=event_label(event),
            trust=event.source_trust,
            risk_tags=event.risk_tags,
            data={
                "event_type": event.event_type.value,
                "timestamp": event.timestamp.isoformat(),
                "payload": event.payload,
                "agent_id": event.agent_id,
                "session_id": event.session_id,
            },
        )

