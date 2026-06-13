import asyncio

from opswitness.core.events import AgentEvent, EventType
from opswitness.mcp.proxy import MCPProxy, MCPProxyConfig
from opswitness.splunk.capabilities import (
    SplunkAnomalyRequest,
    build_native_anomaly_query,
    run_mcp_preflight,
    run_native_anomaly_investigation,
)
from opswitness.splunk.hec import SplunkHECClient, SplunkHECConfig


def test_native_anomaly_query_is_scoped_and_portable() -> None:
    query = build_native_anomaly_query(
        SplunkAnomalyRequest(service="checkout-api", index="main", earliest="-2h")
    )

    assert 'index=main earliest=-2h service="checkout-api"' in query
    assert "eventstats avg(errors) AS baseline stdev(errors) AS sigma" in query
    assert "splunk_run_query" not in query


def test_native_anomaly_query_rejects_unsafe_identifiers() -> None:
    request = SplunkAnomalyRequest(service="checkout-api", index="main | delete")

    try:
        build_native_anomaly_query(request)
    except ValueError as exc:
        assert "index contains unsupported characters" in str(exc)
    else:
        raise AssertionError("unsafe index identifier was accepted")


def test_preflight_and_anomaly_report_unavailable_without_mcp() -> None:
    proxy = MCPProxy(MCPProxyConfig(upstream_url=""))

    preflight, events = asyncio.run(run_mcp_preflight(proxy, "run-preflight"))
    anomaly = asyncio.run(
        run_native_anomaly_investigation(
            proxy,
            SplunkAnomalyRequest(service="checkout-api", run_id="run-anomaly"),
        )
    )

    assert preflight.status == "unavailable"
    assert events == []
    assert anomaly.status == "unavailable"
    assert "did not advertise splunk_run_query" in anomaly.detail


def test_hec_acknowledgement_confirms_indexing(monkeypatch) -> None:
    class Response:
        def __init__(self, body: dict) -> None:
            self.body = body

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self.body

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def post(self, url, **kwargs):
            if url.endswith("/ack"):
                return Response({"acks": {"42": True}})
            return Response({"text": "Success", "code": 0, "ackId": 42})

    monkeypatch.setattr("opswitness.splunk.hec.httpx.AsyncClient", lambda **kwargs: Client())
    client = SplunkHECClient(
        SplunkHECConfig(
            url="https://splunk.example/services/collector/event",
            token="test-token",
            ack_mode="auto",
        )
    )
    event = AgentEvent(
        event_type=EventType.run_started,
        run_id="run-ack",
        session_id="session-ack",
        agent_id="agent-ack",
        node_id="node-ack",
    )

    receipt = asyncio.run(client.send_events([event]))

    assert receipt.status == "indexed"
    assert receipt.ack_ids == [42]
