from pathlib import Path

import pytest

import opswitness.api.app as api_module
from opswitness.core.event_store import JsonEventStore
from opswitness.graph.store import JsonGraphStore
from opswitness.incidents.models import IncidentBriefRequest
from opswitness.incidents.service import IncidentStore, build_incident_brief, rewrite_safe_query
from tests.support import client, request


def test_safe_query_rewrite_scopes_and_removes_raw_export() -> None:
    rewritten = rewrite_safe_query(
        "search index=* earliest=-7d | table _raw user action",
        "checkout-api",
    )

    assert "index=main" in rewritten
    assert "service=checkout-api" in rewritten
    assert "earliest=-30m" in rewritten
    assert "_raw" not in rewritten
    assert "| stats count by action region version" in rewritten


def test_incident_brief_cites_evidence_and_scores_impact() -> None:
    brief = build_incident_brief(
        IncidentBriefRequest(
            run_id="run-incident",
            deployment_id="deploy-1842",
            service="checkout-api",
            version="2.7.1",
            baseline_errors=10,
            current_errors=420,
            affected_services=["checkout-api", "auth-service"],
            affected_regions=["us-east", "eu-west"],
            evidence_node_ids=["search-1", "result-1"],
        )
    )

    assert brief.severity == "critical"
    assert brief.error_multiplier == 42.0
    assert brief.confidence >= 90
    assert brief.evidence_node_ids == ["search-1", "result-1"]


@pytest.mark.anyio
async def test_incident_api_rejects_missing_evidence(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SPLUNK_REQUIRE_HEC", "false")
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    monkeypatch.setattr(api_module, "EVENT_STORE", JsonEventStore(tmp_path / "events"))
    monkeypatch.setattr(api_module, "GRAPH_STORE", JsonGraphStore(tmp_path / "graphs"))
    monkeypatch.setattr(api_module, "INCIDENT_STORE", IncidentStore(tmp_path / "incidents"))
    deployment = await request(
        api_module.app,
        "POST",
        "/integrations/deployments",
        json={
            "deployment_id": "deploy-1842",
            "service": "checkout-api",
            "version": "2.7.1",
            "run_id": "run-incident-api",
        },
    )
    assert deployment.status_code == 200

    response = await request(
        api_module.app,
        "POST",
        "/incidents",
        json={
            "run_id": "run-incident-api",
            "deployment_id": "deploy-1842",
            "service": "checkout-api",
            "version": "2.7.1",
            "baseline_errors": 10,
            "current_errors": 420,
            "evidence_node_ids": ["missing-node"],
            "notify_slack": False,
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"]["missing_evidence_node_ids"] == ["missing-node"]


@pytest.mark.anyio
async def test_incident_api_builds_graph_and_records_approval(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SPLUNK_REQUIRE_HEC", "false")
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    monkeypatch.delenv("SPLUNK_MCP_URL", raising=False)
    monkeypatch.delenv("SPLUNK_MCP_BEARER_TOKEN", raising=False)
    monkeypatch.setattr(api_module, "EVENT_STORE", JsonEventStore(tmp_path / "events"))
    monkeypatch.setattr(api_module, "GRAPH_STORE", JsonGraphStore(tmp_path / "graphs"))
    monkeypatch.setattr(api_module, "INCIDENT_STORE", IncidentStore(tmp_path / "incidents"))
    async with client(api_module.app) as test_client:
        deployment = (
            await test_client.post(
                "/integrations/deployments",
                json={
                    "deployment_id": "deploy-1842",
                    "service": "checkout-api",
                    "version": "2.7.1",
                    "run_id": "run-incident-api",
                },
            )
        ).json()
        incident_response = await test_client.post(
            "/incidents",
            json={
                "run_id": "run-incident-api",
                "deployment_id": "deploy-1842",
                "service": "checkout-api",
                "version": "2.7.1",
                "baseline_errors": 10,
                "current_errors": 420,
                "affected_services": ["checkout-api", "auth-service"],
                "affected_regions": ["us-east"],
                "evidence_node_ids": [deployment["deployment_node_id"]],
                "unsafe_query": "search index=* earliest=-7d | table _raw user",
                "notify_slack": False,
            },
        )
        assert incident_response.status_code == 200
        incident = incident_response.json()

        approval = await test_client.post(
            f"/incidents/{incident['incident_id']}/approval",
            json={"decision": "approved", "approver": "sre-lead"},
        )
        graph = api_module.GRAPH_STORE.load("run-incident-api").model_dump(mode="json")

    assert approval.status_code == 200
    assert approval.json()["approval_status"] == "approved"
    assert {node["type"] for node in graph["nodes"]} >= {
        "Deployment",
        "Incident",
        "RemediationProposal",
        "Approval",
        "ApprovalDecision",
    }
