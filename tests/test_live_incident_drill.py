from pathlib import Path
from types import SimpleNamespace

import pytest

import opswitness.api.app as api_module
from opswitness.core.event_store import JsonEventStore
from opswitness.core.events import AgentEvent, EventType, SourceTrust
from opswitness.graph.store import JsonGraphStore
from opswitness.incidents.service import IncidentStore
from opswitness.integrations.foundation_sec import FoundationSecAssessment, FoundationSecResult
from opswitness.splunk.capabilities import SplunkAnomalyResult, SplunkMCPPreflight
from opswitness.splunk.hec import SplunkHECHealth, SplunkHECReceipt
from opswitness.splunk.governance import MCPToolExecution
from tests.support import request


class FakeHEC:
    config = SimpleNamespace(enabled=True, ack_mode="required")

    async def health(self) -> SplunkHECHealth:
        return SplunkHECHealth(configured=True, reachable=True, detail="ready")

    async def send_events(self, events: list[AgentEvent]) -> SplunkHECReceipt:
        return SplunkHECReceipt(status="indexed", events=len(events))


class FakeSlack:
    configured = True

    async def send_incident(self, incident) -> tuple[str, str]:
        return "sent", "delivered"


class FakeFoundationSec:
    configured = True
    model = "fdtn-ai/Foundation-Sec-1.1-8B-Instruct:test"

    async def assess(self, **kwargs) -> FoundationSecResult:
        return FoundationSecResult(
            status="executed",
            detail="validated",
            model=self.model,
            assessment=FoundationSecAssessment(
                classification="deployment regression",
                severity="high",
                probable_cause="Evidence indicates a release-correlated regression.",
                recommended_action="Validate a scoped rollback.",
                confidence=91,
                evidence_references=kwargs["evidence_references"],
            ),
        )


def configure_stores(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(api_module, "EVENT_STORE", JsonEventStore(tmp_path / "events"))
    monkeypatch.setattr(api_module, "GRAPH_STORE", JsonGraphStore(tmp_path / "graphs"))
    monkeypatch.setattr(api_module, "INCIDENT_STORE", IncidentStore(tmp_path / "incidents"))


def configure_governance(monkeypatch) -> None:
    async def executed(*args, **kwargs):
        return MCPToolExecution(
            status="executed",
            tool_name="splunk_run_query",
            detail="Executed deterministic test governance stage.",
        )

    monkeypatch.setattr(api_module, "run_hosted_model_inference", executed)
    monkeypatch.setattr(api_module, "verify_with_saved_search", executed)
    monkeypatch.setattr(api_module, "discover_kv_policy", executed)


@pytest.mark.anyio
async def test_live_drill_runs_real_integration_pipeline(monkeypatch, tmp_path: Path) -> None:
    configure_stores(monkeypatch, tmp_path)
    configure_governance(monkeypatch)
    monkeypatch.setenv("SPLUNK_MCP_URL", "https://splunk.example/mcp")
    monkeypatch.setenv("SPLUNK_MCP_BEARER_TOKEN", "test-token")
    monkeypatch.setattr(api_module, "splunk_client", lambda: FakeHEC())
    monkeypatch.setattr(api_module, "slack_notifier", lambda: FakeSlack())
    monkeypatch.setattr(api_module, "foundation_sec_client", lambda: FakeFoundationSec())

    async def fake_preflight(proxy, run_id):
        return (
            SplunkMCPPreflight(
                status="ready",
                run_id=run_id,
                available_tools=["splunk_run_query"],
                anomaly_query_supported=True,
            ),
            [
                AgentEvent(
                    event_type=EventType.mcp_tool_available,
                    run_id=run_id,
                    session_id="preflight",
                    agent_id="splunk-mcp",
                    node_id="tool:splunk_run_query",
                    source_trust=SourceTrust.trusted,
                    payload={"tool_name": "splunk_run_query"},
                )
            ],
        )

    async def fake_anomaly(proxy, anomaly_request):
        return SplunkAnomalyResult(
            status="executed",
            run_id=anomaly_request.run_id,
            query="search index=main",
            detail="Executed portable native SPL through Splunk MCP.",
            events=[
                AgentEvent(
                    event_type=EventType.mcp_tool_called,
                    run_id=anomaly_request.run_id,
                    session_id="investigation",
                    agent_id="opswitness-anomaly",
                    node_id="call:splunk_run_query",
                    parent_node_id="tool:splunk_run_query",
                    source_trust=SourceTrust.trusted,
                    payload={"tool_name": "splunk_run_query"},
                ),
                AgentEvent(
                    event_type=EventType.splunk_search_executed,
                    run_id=anomaly_request.run_id,
                    session_id="investigation",
                    agent_id="opswitness-anomaly",
                    node_id="result:splunk_run_query",
                    parent_node_id="call:splunk_run_query",
                    source_trust=SourceTrust.trusted,
                    payload={"status": "executed"},
                ),
            ],
        )

    monkeypatch.setattr(api_module, "run_mcp_preflight", fake_preflight)
    monkeypatch.setattr(api_module, "run_native_anomaly_investigation", fake_anomaly)

    response = await request(api_module.app, "POST", "/drills/live-incident", json={})
    result = response.json()

    assert response.status_code == 200
    assert result["status"] == "completed"
    assert result["scenario"] == "deployment_regression"
    assert [stage["id"] for stage in result["stages"]] == [
        "hec",
        "mcp",
        "spl",
        "foundation_sec",
        "model",
        "verification",
        "policy",
        "deployment",
        "incident",
        "slack",
        "graph",
    ]
    assert result["incident"]["approval_status"] == "pending"
    assert result["incident"]["slack_status"] == "sent"
    graph = api_module.GRAPH_STORE.load(result["run_id"])
    assert {node.type for node in graph.nodes} >= {
        "MCPTool",
        "ToolCall",
        "SplunkResult",
        "Deployment",
        "Incident",
        "RemediationProposal",
        "Approval",
        "Notification",
    }


@pytest.mark.anyio
async def test_live_drill_fails_visibly_without_hec(monkeypatch, tmp_path: Path) -> None:
    configure_stores(monkeypatch, tmp_path)
    configure_governance(monkeypatch)
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    monkeypatch.setenv("SPLUNK_REQUIRE_HEC", "true")

    response = await request(api_module.app, "POST", "/drills/live-incident", json={})
    result = response.json()

    assert response.status_code == 200
    assert result["status"] == "failed"
    assert result["stages"][0]["id"] == "hec"
    assert result["stages"][0]["status"] == "failed"
    assert not api_module.GRAPH_STORE.list()


@pytest.mark.anyio
async def test_unknown_live_drill_job_returns_not_found() -> None:
    response = await request(api_module.app, "GET", "/drills/live-incident/jobs/missing")

    assert response.status_code == 404
    assert response.json()["detail"] == "drill job not found"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("scenario", "service", "title"),
    [
        ("credential_attack", "auth-gateway", "Credential-stuffing attack against authentication"),
        ("queue_saturation", "order-worker", "Order processing queue saturation"),
    ],
)
async def test_live_drill_supports_distinct_scenarios(
    monkeypatch,
    tmp_path: Path,
    scenario: str,
    service: str,
    title: str,
) -> None:
    configure_stores(monkeypatch, tmp_path)
    configure_governance(monkeypatch)
    monkeypatch.setenv("SPLUNK_MCP_URL", "https://splunk.example/mcp")
    monkeypatch.setenv("SPLUNK_MCP_BEARER_TOKEN", "test-token")
    monkeypatch.setattr(api_module, "splunk_client", lambda: FakeHEC())
    monkeypatch.setattr(api_module, "slack_notifier", lambda: FakeSlack())
    monkeypatch.setattr(api_module, "foundation_sec_client", lambda: FakeFoundationSec())

    async def fake_preflight(proxy, run_id):
        return (
            SplunkMCPPreflight(
                status="ready",
                run_id=run_id,
                available_tools=["splunk_run_query"],
                anomaly_query_supported=True,
            ),
            [],
        )

    async def fake_anomaly(proxy, anomaly_request):
        assert anomaly_request.service == service
        return SplunkAnomalyResult(
            status="executed",
            run_id=anomaly_request.run_id,
            query="search index=main",
            detail="Executed scenario SPL.",
            events=[],
        )

    monkeypatch.setattr(api_module, "run_mcp_preflight", fake_preflight)
    monkeypatch.setattr(api_module, "run_native_anomaly_investigation", fake_anomaly)

    response = await request(
        api_module.app,
        "POST",
        "/drills/live-incident",
        json={"scenario": scenario},
    )
    result = response.json()

    assert result["status"] == "completed"
    assert result["scenario"] == scenario
    assert result["incident"]["title"] == title
