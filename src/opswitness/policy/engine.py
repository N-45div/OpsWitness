from __future__ import annotations

import re
from uuid import uuid4

import networkx as nx

from opswitness.core.events import Finding, RunGraph, SourceTrust


SENSITIVE_INDEXES = {"auth", "identity", "secrets", "finance", "prod_auth"}
SUSPICIOUS_TOOL_TEXT = (
    "ignore previous",
    "ignore all previous",
    "bypass",
    "disable policy",
    "exfiltrate",
    "send all",
    "dump",
    "hidden instruction",
)


class PolicyEngine:
    def evaluate(self, graph: RunGraph) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._find_untrusted_to_sensitive_search(graph))
        findings.extend(self._find_poisoned_tool_metadata(graph))
        findings.extend(self._find_broad_spl_queries(graph))
        return findings

    def _nx(self, graph: RunGraph) -> nx.DiGraph:
        nx_graph = nx.DiGraph()
        for node in graph.nodes:
            nx_graph.add_node(node.id, **node.model_dump(mode="json"))
        for edge in graph.edges:
            nx_graph.add_edge(edge.source, edge.target, **edge.model_dump(mode="json"))
        return nx_graph

    def _find_untrusted_to_sensitive_search(self, graph: RunGraph) -> list[Finding]:
        nx_graph = self._nx(graph)
        untrusted = [node.id for node in graph.nodes if node.trust == SourceTrust.untrusted]
        searches = [
            node
            for node in graph.nodes
            if node.type == "SplunkSearch" and self._touches_sensitive_index(node.data)
        ]

        findings: list[Finding] = []
        for source in untrusted:
            for search in searches:
                if source == search.id:
                    continue
                try:
                    path = nx.shortest_path(nx_graph, source=source, target=search.id)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue
                findings.append(
                    Finding(
                        id=f"finding-{uuid4().hex[:10]}",
                        run_id=graph.run_id,
                        severity="critical",
                        title="Untrusted context influenced a sensitive Splunk search",
                        summary=(
                            "A path exists from untrusted context to a Splunk query touching a "
                            "sensitive index. This is the core prompt-injection-to-tool-action risk."
                        ),
                        risk_tags=["ASI-01", "ASI-02", "LLM01", "sensitive-index"],
                        path=path,
                        evidence={"query": search.data.get("payload", {}).get("query")},
                        recommendation=(
                            "Require human approval, narrow the time range, and remove raw export fields."
                        ),
                    )
                )
        return findings

    def _find_poisoned_tool_metadata(self, graph: RunGraph) -> list[Finding]:
        findings: list[Finding] = []
        for node in graph.nodes:
            if node.type != "MCPTool":
                continue
            metadata = " ".join(
                str(node.data.get("payload", {}).get(key, ""))
                for key in ("tool_name", "description", "schema")
            ).lower()
            matched = [term for term in SUSPICIOUS_TOOL_TEXT if term in metadata]
            if matched:
                findings.append(
                    Finding(
                        id=f"finding-{uuid4().hex[:10]}",
                        run_id=graph.run_id,
                        severity="high",
                        title="Suspicious MCP tool metadata",
                        summary="Tool metadata contains instruction-like text that can poison agent decisions.",
                        risk_tags=["tool-poisoning", "ASI-02", "LLM01"],
                        path=[node.id],
                        evidence={"matched_terms": matched, "tool": node.label},
                        recommendation="Review the MCP server/tool source and hide untrusted tool metadata.",
                    )
                )
        return findings

    def _find_broad_spl_queries(self, graph: RunGraph) -> list[Finding]:
        findings: list[Finding] = []
        for node in graph.nodes:
            if node.type != "SplunkSearch":
                continue
            query = str(node.data.get("payload", {}).get("query", ""))
            issues = self._spl_issues(query)
            if issues:
                findings.append(
                    Finding(
                        id=f"finding-{uuid4().hex[:10]}",
                        run_id=graph.run_id,
                        severity="high" if "index=*" in issues else "medium",
                        title="Risky SPL pattern",
                        summary="The generated SPL is broader or more extractive than expected.",
                        risk_tags=["spl-risk", "excessive-agency"],
                        path=[node.id],
                        evidence={"query": query, "issues": issues},
                        recommendation="Replace broad index scope and raw exports with scoped fields/time windows.",
                    )
                )
        return findings

    def _touches_sensitive_index(self, data: dict) -> bool:
        query = str(data.get("payload", {}).get("query", "")).lower()
        for index in SENSITIVE_INDEXES:
            if re.search(rf"\bindex\s*=\s*{re.escape(index)}\b", query):
                return True
        return False

    def _spl_issues(self, query: str) -> list[str]:
        normalized = query.lower()
        issues: list[str] = []
        if "index=*" in normalized:
            issues.append("index=*")
        if "table _raw" in normalized or "fields _raw" in normalized:
            issues.append("_raw export")
        if re.search(r"earliest\s*=\s*-\d+\s*(d|w|mon|y)\b", normalized):
            issues.append("long time range")
        if "| outputcsv" in normalized or "| outputlookup" in normalized:
            issues.append("data export command")
        return issues
