import pytest

from opswitness.api.app import app
from tests.support import request


@pytest.mark.anyio
async def test_mcp_trace_fails_closed_without_splunk_hec(monkeypatch) -> None:
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    monkeypatch.setenv("SPLUNK_REQUIRE_HEC", "true")

    response = await request(
        app,
        "POST",
        "/mcp/trace",
        json={
            "direction": "client_to_server",
            "run_id": "run-ci",
            "session_id": "session-ci",
            "agent_id": "agent-ci",
            "message": {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        },
    )

    assert response.status_code == 503
    assert "Splunk HEC is required" in response.json()["detail"]


@pytest.mark.anyio
async def test_raw_mcp_proxy_fails_closed_before_upstream(monkeypatch) -> None:
    monkeypatch.delenv("SPLUNK_HEC_URL", raising=False)
    monkeypatch.delenv("SPLUNK_HEC_TOKEN", raising=False)
    monkeypatch.setenv("SPLUNK_REQUIRE_HEC", "true")
    monkeypatch.setenv("SPLUNK_MCP_URL", "https://example.invalid/mcp")

    response = await request(
        app,
        "POST",
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )

    assert response.status_code == 503
    assert "Splunk HEC is required" in response.json()["detail"]


@pytest.mark.anyio
async def test_raw_mcp_proxy_requires_upstream_when_evidence_is_disabled_for_local_test(
    monkeypatch,
) -> None:
    monkeypatch.setenv("SPLUNK_REQUIRE_HEC", "false")
    monkeypatch.delenv("SPLUNK_MCP_URL", raising=False)

    response = await request(
        app,
        "POST",
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == "SPLUNK_MCP_URL is not configured"
