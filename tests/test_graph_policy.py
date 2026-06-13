from pathlib import Path

from opswitness.core.io import read_jsonl_events
from opswitness.graph.builder import GraphBuilder
from opswitness.mcp.normalizer import MCPTraceNormalizer


def test_unsafe_trace_produces_critical_finding() -> None:
    events = read_jsonl_events(Path("tests/fixtures/unsafe-run.jsonl"))
    graph = GraphBuilder().build(events)[0]

    assert graph.run_id == "run-unsafe-001"
    assert any(finding.severity == "critical" for finding in graph.findings)
    assert any("tool-poisoning" in finding.risk_tags for finding in graph.findings)


def test_safe_trace_has_no_policy_findings() -> None:
    events = read_jsonl_events(Path("tests/fixtures/safe-run.jsonl"))
    graph = GraphBuilder().build(events)[0]

    assert graph.run_id == "run-safe-001"
    assert graph.findings == []


def test_mcp_tool_call_normalizes_splunk_search() -> None:
    events = MCPTraceNormalizer().normalize(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "splunk_search",
                "arguments": {"query": "search index=auth earliest=-7d | table _raw user"},
            },
        },
        direction="client_to_server",
        run_id="run-mcp-001",
        session_id="session-mcp-001",
        agent_id="agent-mcp",
    )

    assert [event.event_type.value for event in events] == [
        "mcp.tool.called",
        "splunk.search.generated",
    ]
    assert events[1].payload["query"] == "search index=auth earliest=-7d | table _raw user"


def test_live_splunk_mcp_tool_name_normalizes_query() -> None:
    events = MCPTraceNormalizer().normalize(
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "splunk_run_query",
                "arguments": {"query": 'search index=main "opswitness-live-hec-check" | head 1'},
            },
        },
        direction="client_to_server",
        run_id="run-mcp-live-name",
        session_id="session-mcp-live-name",
        agent_id="agent-mcp",
    )

    assert [event.event_type.value for event in events] == [
        "mcp.tool.called",
        "splunk.search.generated",
    ]
    assert events[0].payload["tool_name"] == "splunk_run_query"
