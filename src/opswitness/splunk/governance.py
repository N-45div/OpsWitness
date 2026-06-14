from __future__ import annotations

import os
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from opswitness.core.events import AgentEvent
from opswitness.mcp.proxy import MCPProxy


SAVED_SEARCH_BY_SCENARIO = {
    "deployment_regression": "OpsWitness - Verify Deployment Regression",
    "credential_attack": "OpsWitness - Verify Credential Attack",
    "queue_saturation": "OpsWitness - Verify Queue Saturation",
}


class MCPToolExecution(BaseModel):
    status: Literal["executed", "unavailable"]
    tool_name: str
    detail: str
    response: Any | None = None
    events: list[AgentEvent] = Field(default_factory=list, exclude=True)


async def execute_mcp_tool(
    proxy: MCPProxy,
    *,
    tool_name: str,
    arguments: dict[str, Any],
    run_id: str,
    agent_id: str,
) -> MCPToolExecution:
    if not proxy.config.enabled:
        return MCPToolExecution(
            status="unavailable",
            tool_name=tool_name,
            detail="Splunk MCP is not configured.",
        )
    session_id = f"governance-{uuid4().hex[:10]}"
    events: list[AgentEvent] = []
    initialized, initialized_events = await proxy.forward(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "opswitness-governance", "version": "0.2.0"},
            },
        },
        run_id=run_id,
        session_id=session_id,
        agent_id=agent_id,
    )
    events.extend(initialized_events)
    headers = initialized.headers
    _, notification_events = await proxy.forward(
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        run_id=run_id,
        session_id=session_id,
        agent_id=agent_id,
        headers=headers,
    )
    events.extend(notification_events)
    listing, listing_events = await proxy.forward(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        run_id=run_id,
        session_id=session_id,
        agent_id=agent_id,
        headers=headers,
    )
    events.extend(listing_events)
    tools = listing.body.get("result", {}).get("tools", []) if isinstance(listing.body, dict) else []
    available = {tool.get("name") for tool in tools if isinstance(tool, dict)}
    if tool_name not in available:
        return MCPToolExecution(
            status="unavailable",
            tool_name=tool_name,
            detail=f"Splunk MCP did not advertise {tool_name}.",
            events=events,
        )
    response, response_events = await proxy.forward(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        },
        run_id=run_id,
        session_id=session_id,
        agent_id=agent_id,
        headers=headers,
    )
    events.extend(response_events)
    result = response.body.get("result") if isinstance(response.body, dict) else None
    structured = result.get("structuredContent") if isinstance(result, dict) else None
    status_code = structured.get("status_code") if isinstance(structured, dict) else None
    if isinstance(result, dict) and (
        result.get("isError") is True or isinstance(status_code, int) and status_code >= 400
    ):
        return MCPToolExecution(
            status="unavailable",
            tool_name=tool_name,
            detail=f"Splunk MCP returned an error while executing {tool_name}.",
            response=response.body,
            events=events,
        )
    return MCPToolExecution(
        status="executed",
        tool_name=tool_name,
        detail=f"Executed {tool_name} through Splunk MCP.",
        response=response.body,
        events=events,
    )


async def verify_with_saved_search(
    proxy: MCPProxy,
    *,
    scenario: str,
    service: str,
    index: str,
    run_id: str,
) -> MCPToolExecution:
    return await execute_mcp_tool(
        proxy,
        tool_name="splunk_run_saved_search",
        arguments={
            "saved_search_name": SAVED_SEARCH_BY_SCENARIO[scenario],
            "app": os.getenv("SPLUNK_OPSWITNESS_APP", "opswitness"),
            "args": f'service="{service}" index="{index}"',
            "row_limit": 100,
        },
        run_id=run_id,
        agent_id="opswitness-approved-detection",
    )


async def discover_kv_policy(proxy: MCPProxy, *, service: str, run_id: str) -> MCPToolExecution:
    safe_service = service.replace('"', '\\"')
    return await execute_mcp_tool(
        proxy,
        tool_name="splunk_run_query",
        arguments={
            "query": (
                f'| inputlookup opswitness_service_policy_lookup '
                f'| search service="{safe_service}" | head 1'
            ),
            "row_limit": 1,
        },
        run_id=run_id,
        agent_id="opswitness-policy",
    )


async def run_hosted_model_inference(
    proxy: MCPProxy,
    *,
    scenario_query: str,
    run_id: str,
) -> MCPToolExecution:
    model_name = os.getenv("SPLUNK_HOSTED_MODEL_NAME", "").strip()
    if not model_name:
        return await execute_mcp_tool(
            proxy,
            tool_name="splunk_run_query",
            arguments={
                "query": f"{scenario_query} | anomalydetection method=zscore action=annotate",
                "row_limit": 100,
            },
            run_id=run_id,
            agent_id="opswitness-hosted-model",
        )
    safe_model_name = model_name.replace('"', '\\"')
    return await execute_mcp_tool(
        proxy,
        tool_name="splunk_run_query",
        arguments={"query": f'{scenario_query} | apply "{safe_model_name}"', "row_limit": 100},
        run_id=run_id,
        agent_id="opswitness-hosted-model",
    )


async def persist_model_feedback(
    proxy: MCPProxy,
    *,
    run_id: str,
    scenario: str,
    accepted: bool,
    reviewer: str,
) -> MCPToolExecution:
    safe_run_id = run_id.replace('"', '\\"')
    safe_scenario = scenario.replace('"', '\\"')
    safe_reviewer = reviewer.replace('"', '\\"')
    query = (
        "| makeresults "
        f'| eval run_id="{safe_run_id}", model_name="splunk-native-anomalydetection", '
        f'classification="{safe_scenario}", accepted={"true" if accepted else "false"}, '
        f'reviewer="{safe_reviewer}", reviewed_at=now() '
        "| fields run_id model_name classification accepted reviewer reviewed_at "
        "| outputlookup append=true opswitness_model_feedback_lookup"
    )
    return await execute_mcp_tool(
        proxy,
        tool_name="splunk_run_query",
        arguments={"query": query, "row_limit": 1},
        run_id=run_id,
        agent_id="opswitness-feedback",
    )
