from __future__ import annotations

import re
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from opswitness.core.events import AgentEvent
from opswitness.mcp.proxy import MCPProxy


PREFLIGHT_TOOLS = (
    "splunk_get_info",
    "splunk_get_indexes",
    "splunk_get_metadata",
    "splunk_get_user_info",
)


class SplunkMCPPreflight(BaseModel):
    status: Literal["ready", "partial", "unavailable"]
    run_id: str
    available_tools: list[str] = Field(default_factory=list)
    executed_tools: list[str] = Field(default_factory=list)
    skipped_contextual_tools: list[str] = Field(default_factory=list)
    unavailable_tools: list[str] = Field(default_factory=list)
    anomaly_query_supported: bool = False
    mltk_algorithms: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class SplunkAnomalyRequest(BaseModel):
    service: str
    index: str = "main"
    service_field: str = "service"
    earliest: str = "-60m"
    signal: Literal["error_spike", "auth_failures", "queue_saturation"] = "error_spike"
    run_id: str | None = None
    execute: bool = True


class SplunkAnomalyResult(BaseModel):
    status: Literal["executed", "query_only", "unavailable"]
    run_id: str
    query: str
    detail: str
    response: Any | None = None
    events: list[AgentEvent] = Field(default_factory=list, exclude=True)


async def run_mcp_preflight(proxy: MCPProxy, run_id: str | None = None) -> tuple[SplunkMCPPreflight, list[AgentEvent]]:
    preflight, events, _, _ = await _discover_mcp(proxy, run_id)
    return preflight, events


async def _discover_mcp(
    proxy: MCPProxy,
    run_id: str | None = None,
) -> tuple[SplunkMCPPreflight, list[AgentEvent], dict[str, str], str]:
    run = run_id or f"preflight-{uuid4().hex[:12]}"
    session = f"preflight-session-{uuid4().hex[:12]}"
    if not proxy.config.enabled:
        return SplunkMCPPreflight(status="unavailable", run_id=run), [], {}, session

    events: list[AgentEvent] = []
    headers: dict[str, str] = {}
    initialized, initialized_events = await proxy.forward(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "opswitness-preflight", "version": "0.1.0"},
            },
        },
        run_id=run,
        session_id=session,
        agent_id="opswitness-preflight",
    )
    events.extend(initialized_events)
    headers.update(initialized.headers)
    _, notification_events = await proxy.forward(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        run_id=run,
        session_id=session,
        agent_id="opswitness-preflight",
        headers=headers,
    )
    events.extend(notification_events)

    listing, listing_events = await proxy.forward(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        run_id=run,
        session_id=session,
        agent_id="opswitness-preflight",
        headers=headers,
    )
    events.extend(listing_events)
    tools = _extract_tools(listing.body)
    available = sorted(tool["name"] for tool in tools if isinstance(tool.get("name"), str))
    tools_by_name = {tool["name"]: tool for tool in tools if isinstance(tool.get("name"), str)}
    details: dict[str, Any] = {}
    executed: list[str] = []
    skipped_contextual: list[str] = []
    for offset, tool_name in enumerate(PREFLIGHT_TOOLS, start=3):
        if tool_name not in available:
            continue
        input_schema = tools_by_name[tool_name].get("inputSchema", {})
        required = input_schema.get("required", []) if isinstance(input_schema, dict) else []
        if required:
            skipped_contextual.append(tool_name)
            continue
        response, response_events = await proxy.forward(
            {
                "jsonrpc": "2.0",
                "id": offset,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": {}},
            },
            run_id=run,
            session_id=session,
            agent_id="opswitness-preflight",
            headers=headers,
        )
        events.extend(response_events)
        executed.append(tool_name)
        details[tool_name] = response.body

    mltk_algorithms: list[str] = []
    if "splunk_get_knowledge_objects" in available:
        response, response_events = await proxy.forward(
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "splunk_get_knowledge_objects",
                    "arguments": {"type": "mltk_algorithms", "row_limit": 100},
                },
            },
            run_id=run,
            session_id=session,
            agent_id="opswitness-preflight",
            headers=headers,
        )
        events.extend(response_events)
        executed.append("splunk_get_knowledge_objects:mltk_algorithms")
        details["mltk_algorithms"] = response.body
        structured = (
            response.body.get("result", {}).get("structuredContent", {})
            if isinstance(response.body, dict)
            else {}
        )
        results = structured.get("results", []) if isinstance(structured, dict) else []
        mltk_algorithms = sorted(
            item["name"]
            for item in results
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        )

    unavailable = [tool for tool in PREFLIGHT_TOOLS if tool not in available]
    return (
        SplunkMCPPreflight(
            status="ready" if not unavailable else "partial",
            run_id=run,
            available_tools=available,
            executed_tools=executed,
            skipped_contextual_tools=skipped_contextual,
            unavailable_tools=unavailable,
            anomaly_query_supported="splunk_run_query" in available,
            mltk_algorithms=mltk_algorithms,
            details=details,
        ),
        events,
        headers,
        session,
    )


async def run_native_anomaly_investigation(
    proxy: MCPProxy,
    request: SplunkAnomalyRequest,
) -> SplunkAnomalyResult:
    run = request.run_id or f"anomaly-{uuid4().hex[:12]}"
    query = build_native_anomaly_query(request)
    if not request.execute:
        return SplunkAnomalyResult(
            status="query_only",
            run_id=run,
            query=query,
            detail="Portable native SPL generated without executing it.",
        )

    preflight, preflight_events, headers, session = await _discover_mcp(proxy, run)
    if not preflight.anomaly_query_supported:
        return SplunkAnomalyResult(
            status="unavailable",
            run_id=run,
            query=query,
            detail="Splunk MCP did not advertise splunk_run_query; query was not executed.",
            events=preflight_events,
        )
    response, query_events = await proxy.forward(
        {
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {"name": "splunk_run_query", "arguments": {"query": query}},
        },
        run_id=run,
        session_id=session,
        agent_id="opswitness-anomaly",
        headers=headers,
    )
    return SplunkAnomalyResult(
        status="executed",
        run_id=run,
        query=query,
        detail="Executed portable native SPL through Splunk MCP.",
        response=response.body,
        events=preflight_events + query_events,
    )


def build_native_anomaly_query(request: SplunkAnomalyRequest) -> str:
    index = _safe_identifier(request.index, "index")
    service_field = _safe_identifier(request.service_field, "service_field")
    earliest = _safe_earliest(request.earliest)
    service = request.service.replace("\\", "\\\\").replace('"', '\\"')
    prefix = f'search index={index} earliest={earliest} {service_field}="{service}" '
    if request.signal == "auth_failures":
        return (
            prefix
            + '(action="login_failed" OR status=401 OR status=403) '
            "| bin _time span=5m "
            "| stats count AS failures dc(src_ip) AS source_ips by _time "
            "| eventstats avg(failures) AS baseline stdev(failures) AS sigma "
            "| eval anomaly=if(failures > baseline + (2*sigma), 1, 0) "
            "| where anomaly=1 "
            "| sort - _time"
        )
    if request.signal == "queue_saturation":
        return (
            prefix
            + "(queue_depth>0 OR duration_ms>0) "
            "| bin _time span=5m "
            "| stats max(queue_depth) AS queue_depth p95(duration_ms) AS p95_latency by _time "
            "| eventstats avg(queue_depth) AS baseline stdev(queue_depth) AS sigma "
            "| eval anomaly=if(queue_depth > baseline + (2*sigma), 1, 0) "
            "| where anomaly=1 "
            "| sort - _time"
        )
    return (
        prefix
        + '(level="error" OR status>=500) '
        "| bin _time span=5m "
        "| stats count AS errors by _time "
        "| eventstats avg(errors) AS baseline stdev(errors) AS sigma "
        "| eval anomaly=if(errors > baseline + (2*sigma), 1, 0) "
        "| where anomaly=1 "
        "| sort - _time"
    )


def _safe_identifier(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
        raise ValueError(f"{label} contains unsupported characters")
    return value


def _safe_earliest(value: str) -> str:
    if not re.fullmatch(r"-[0-9]+[smhdw]", value):
        raise ValueError("earliest must be a relative Splunk time such as -60m or -2h")
    return value


def _extract_tools(body: Any) -> list[dict[str, Any]]:
    if not isinstance(body, dict):
        return []
    result = body.get("result")
    if not isinstance(result, dict):
        return []
    tools = result.get("tools")
    return tools if isinstance(tools, list) else []
