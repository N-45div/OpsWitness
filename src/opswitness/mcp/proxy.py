from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import httpx
from pydantic import BaseModel

from opswitness.core.events import AgentEvent
from opswitness.mcp.normalizer import MCPTraceNormalizer


@dataclass(frozen=True)
class MCPProxyConfig:
    upstream_url: str
    bearer_token: str = ""
    verify_tls: bool = True

    @property
    def enabled(self) -> bool:
        return bool(self.upstream_url)


class MCPUpstreamResponse(BaseModel):
    body: Any
    raw_body: bytes
    status_code: int
    content_type: str
    headers: dict[str, str]


class MCPProxy:
    def __init__(self, config: MCPProxyConfig) -> None:
        self.config = config
        self.normalizer = MCPTraceNormalizer()

    async def forward(
        self,
        message: Any,
        *,
        run_id: str | None,
        session_id: str | None,
        agent_id: str,
        headers: dict[str, str] | None = None,
    ) -> tuple[MCPUpstreamResponse, list[AgentEvent]]:
        if not self.config.enabled:
            raise RuntimeError("SPLUNK_MCP_URL is not configured")

        run = run_id or f"run-{uuid4().hex[:12]}"
        session = session_id or f"mcp-session-{uuid4().hex[:12]}"
        request_events = self.normalizer.normalize(
            message,
            direction="client_to_server",
            run_id=run,
            session_id=session,
            agent_id=agent_id,
        )

        upstream = await self._post_upstream(message, headers=headers)
        response_events = self.normalizer.normalize(
            upstream.body,
            direction="server_to_client",
            run_id=run,
            session_id=session,
            agent_id=agent_id,
            parent_node_id=request_events[-1].node_id if request_events else None,
        )
        return upstream, request_events + response_events

    async def _post_upstream(
        self, message: Any, *, headers: dict[str, str] | None
    ) -> MCPUpstreamResponse:
        outbound_headers = {
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
        }
        if headers:
            for key in ("mcp-session-id", "mcp-protocol-version"):
                if key in headers:
                    outbound_headers[key] = headers[key]
        if self.config.bearer_token:
            outbound_headers["authorization"] = f"Bearer {self.config.bearer_token}"

        async with httpx.AsyncClient(verify=self.config.verify_tls, timeout=60) as client:
            response = await client.post(self.config.upstream_url, headers=outbound_headers, json=message)
        response.raise_for_status()
        response_headers = {
            key: value
            for key, value in response.headers.items()
            if key.lower() in {"mcp-session-id", "mcp-protocol-version"}
        }
        try:
            body = response.json()
        except ValueError:
            body = {"raw": response.text, "content_type": response.headers.get("content-type")}
        return MCPUpstreamResponse(
            body=body,
            raw_body=response.content,
            status_code=response.status_code,
            content_type=response.headers.get("content-type", "application/json"),
            headers=response_headers,
        )
