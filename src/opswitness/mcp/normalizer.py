from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from opswitness.core.events import AgentEvent, EventType, SourceTrust


JsonRpcDirection = Literal["client_to_server", "server_to_client"]


class MCPTraceNormalizer:
    def normalize(
        self,
        message: Any,
        *,
        direction: JsonRpcDirection,
        run_id: str,
        session_id: str,
        agent_id: str,
        parent_node_id: str | None = None,
    ) -> list[AgentEvent]:
        messages = message if isinstance(message, list) else [message]
        events: list[AgentEvent] = []
        for item in messages:
            if not isinstance(item, dict):
                continue
            events.extend(
                self._normalize_one(
                    item,
                    direction=direction,
                    run_id=run_id,
                    session_id=session_id,
                    agent_id=agent_id,
                    parent_node_id=parent_node_id,
                )
            )
        return events

    def _normalize_one(
        self,
        message: dict[str, Any],
        *,
        direction: JsonRpcDirection,
        run_id: str,
        session_id: str,
        agent_id: str,
        parent_node_id: str | None,
    ) -> list[AgentEvent]:
        method = message.get("method")
        if direction == "client_to_server" and method == "initialize":
            return [
                self._event(
                    EventType.run_started,
                    run_id,
                    session_id,
                    agent_id,
                    parent_node_id,
                    SourceTrust.trusted,
                    [],
                    {
                        "transport": "mcp-json-rpc",
                        "method": method,
                        "protocol_version": message.get("params", {}).get("protocolVersion"),
                        "client_info": message.get("params", {}).get("clientInfo"),
                    },
                    suffix="initialize",
                )
            ]

        if direction == "client_to_server" and method == "tools/list":
            return [
                self._event(
                    EventType.mcp_tool_selected,
                    run_id,
                    session_id,
                    agent_id,
                    parent_node_id,
                    SourceTrust.unknown,
                    [],
                    {"method": method, "jsonrpc_id": message.get("id")},
                    suffix="tools-list-request",
                )
            ]

        if direction == "server_to_client" and "result" in message:
            tools = message.get("result", {}).get("tools")
            if isinstance(tools, list):
                return [
                    self._event(
                        EventType.mcp_tool_available,
                        run_id,
                        session_id,
                        agent_id,
                        parent_node_id,
                        self._tool_trust(tool),
                        self._tool_risk_tags(tool),
                        {
                            "jsonrpc_id": message.get("id"),
                            "tool_name": tool.get("name"),
                            "description": tool.get("description"),
                            "schema": tool.get("inputSchema"),
                        },
                        suffix=f"tool-{tool.get('name', 'unknown')}",
                    )
                    for tool in tools
                    if isinstance(tool, dict)
                ]

        if direction == "client_to_server" and method == "tools/call":
            params = message.get("params") if isinstance(message.get("params"), dict) else {}
            tool_name = str(params.get("name", "unknown_tool"))
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            call_event = self._event(
                EventType.mcp_tool_called,
                run_id,
                session_id,
                agent_id,
                parent_node_id,
                SourceTrust.unknown,
                self._call_risk_tags(tool_name, arguments),
                {
                    "method": method,
                    "jsonrpc_id": message.get("id"),
                    "tool_name": tool_name,
                    "parameters": arguments,
                },
                suffix=f"call-{tool_name}",
            )
            events = [call_event]
            query = self._extract_splunk_query(tool_name, arguments)
            if query:
                events.append(
                    self._event(
                        EventType.splunk_search_generated,
                        run_id,
                        session_id,
                        agent_id,
                        call_event.node_id,
                        SourceTrust.unknown,
                        [],
                        {"query": query, "tool_name": tool_name, "jsonrpc_id": message.get("id")},
                        suffix=f"search-{tool_name}",
                    )
                )
            return events

        if direction == "server_to_client" and "result" in message:
            result = message.get("result")
            if self._looks_like_tool_result(result):
                return [
                    self._event(
                        EventType.splunk_search_executed,
                        run_id,
                        session_id,
                        agent_id,
                        parent_node_id,
                        SourceTrust.trusted,
                        [],
                        {
                            "jsonrpc_id": message.get("id"),
                            "status": "returned",
                            "result": result,
                        },
                        suffix="tool-result",
                    )
                ]

        return []

    def _event(
        self,
        event_type: EventType,
        run_id: str,
        session_id: str,
        agent_id: str,
        parent_node_id: str | None,
        trust: SourceTrust,
        risk_tags: list[str],
        payload: dict[str, Any],
        *,
        suffix: str,
    ) -> AgentEvent:
        stable_part = str(payload.get("jsonrpc_id") or uuid4().hex[:8])
        return AgentEvent(
            event_type=event_type,
            run_id=run_id,
            session_id=session_id,
            agent_id=agent_id,
            node_id=f"{event_type.value}:{suffix}:{stable_part}",
            parent_node_id=parent_node_id,
            timestamp=datetime.now(timezone.utc),
            source_trust=trust,
            risk_tags=risk_tags,
            payload=payload,
        )

    def _tool_trust(self, tool: dict[str, Any]) -> SourceTrust:
        description = str(tool.get("description", "")).lower()
        if any(term in description for term in ("ignore previous", "bypass", "disable policy")):
            return SourceTrust.untrusted
        return SourceTrust.unknown

    def _tool_risk_tags(self, tool: dict[str, Any]) -> list[str]:
        text = f"{tool.get('name', '')} {tool.get('description', '')}".lower()
        tags: list[str] = []
        if any(term in text for term in ("ignore previous", "bypass", "disable policy", "dump")):
            tags.append("tool-poisoning")
        if str(tool.get("name", "")).startswith("saia_"):
            tags.append("splunk-ai-assistant")
        return tags

    def _call_risk_tags(self, tool_name: str, arguments: dict[str, Any]) -> list[str]:
        tags: list[str] = []
        if tool_name in {
            "splunk_search",
            "splunk_run_query",
            "splunk_get_indexes",
            "splunk_get_metadata",
            "saia_generate_spl",
            "saia_explain_spl",
        }:
            tags.append("splunk-mcp")
        query = self._extract_splunk_query(tool_name, arguments)
        if query and "index=*" in query.lower():
            tags.append("broad-search")
        return tags

    def _extract_splunk_query(self, tool_name: str, arguments: dict[str, Any]) -> str | None:
        if tool_name not in {
            "splunk_search",
            "splunk_run_query",
            "search",
            "saia_explain_spl",
            "saia_optimize_spl",
        }:
            return None
        for key in ("query", "search", "spl", "search_query"):
            value = arguments.get(key)
            if isinstance(value, str) and value.strip():
                return value
        return None

    def _looks_like_tool_result(self, result: Any) -> bool:
        if not isinstance(result, dict):
            return False
        return "content" in result or "structuredContent" in result or "isError" in result
