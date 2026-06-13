from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from opswitness.core.events import AgentEvent


@dataclass(frozen=True)
class OpsWitnessClient:
    """Small builder-facing client for sending real agent traces to OpsWitness."""

    base_url: str
    timeout: float = 15

    def send_events(self, events: list[AgentEvent]) -> dict[str, int]:
        response = httpx.post(
            f"{self.base_url.rstrip('/')}/events",
            json=[event.model_dump(mode="json") for event in events],
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def trace_mcp(
        self,
        message: dict[str, Any] | list[Any],
        *,
        direction: str,
        run_id: str,
        session_id: str,
        agent_id: str,
        parent_node_id: str | None = None,
    ) -> dict[str, int]:
        response = httpx.post(
            f"{self.base_url.rstrip('/')}/mcp/trace",
            json={
                "message": message,
                "direction": direction,
                "run_id": run_id,
                "session_id": session_id,
                "agent_id": agent_id,
                "parent_node_id": parent_node_id,
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

