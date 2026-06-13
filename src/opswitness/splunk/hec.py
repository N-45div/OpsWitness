from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field

from opswitness.core.events import AgentEvent


@dataclass(frozen=True)
class SplunkHECConfig:
    url: str
    token: str
    index: str = "opswitness"
    verify_tls: bool = True
    ack_mode: Literal["auto", "required", "disabled"] = "auto"
    ack_timeout_seconds: float = 10

    def __post_init__(self) -> None:
        if self.ack_mode not in {"auto", "required", "disabled"}:
            raise ValueError("SPLUNK_HEC_ACK_MODE must be auto, required, or disabled")
        if self.ack_timeout_seconds <= 0:
            raise ValueError("SPLUNK_HEC_ACK_TIMEOUT_SECONDS must be greater than zero")

    @property
    def enabled(self) -> bool:
        return bool(self.url and self.token)


class SplunkHECClient:
    def __init__(self, config: SplunkHECConfig) -> None:
        self.config = config

    async def send_events(self, events: list[AgentEvent]) -> "SplunkHECReceipt":
        if not self.config.enabled:
            return SplunkHECReceipt(status="not_configured", events=len(events))
        headers = {"Authorization": f"Splunk {self.config.token}"}
        request_channel = str(uuid4())
        if self.config.ack_mode != "disabled":
            headers["X-Splunk-Request-Channel"] = request_channel
        ack_ids: list[int] = []
        async with httpx.AsyncClient(verify=self.config.verify_tls, timeout=15) as client:
            for event in events:
                response = await client.post(
                    self.config.url,
                    headers=headers,
                    json=event.splunk_event(self.config.index),
                )
                response.raise_for_status()
                ack_id = response.json().get("ackId")
                if isinstance(ack_id, int):
                    ack_ids.append(ack_id)
            if ack_ids:
                indexed = await self._wait_for_ack(client, headers, ack_ids)
                if indexed:
                    return SplunkHECReceipt(status="indexed", events=len(events), ack_ids=ack_ids)
                if self.config.ack_mode == "required":
                    raise RuntimeError("Splunk HEC accepted evidence but index acknowledgement timed out")
                return SplunkHECReceipt(
                    status="accepted_unconfirmed",
                    events=len(events),
                    ack_ids=ack_ids,
                    detail="Indexer acknowledgement timed out; evidence was accepted by HEC.",
                )
        if self.config.ack_mode == "required":
            raise RuntimeError("Splunk HEC index acknowledgement is required but no ackId was returned")
        return SplunkHECReceipt(
            status="accepted",
            events=len(events),
            detail="HEC accepted evidence; index acknowledgement is unavailable or disabled.",
        )

    async def _wait_for_ack(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        ack_ids: list[int],
    ) -> bool:
        ack_url = self.config.url.replace("/services/collector/event", "/services/collector/ack")
        deadline = asyncio.get_running_loop().time() + self.config.ack_timeout_seconds
        while asyncio.get_running_loop().time() < deadline:
            response = await client.post(ack_url, headers=headers, json={"acks": ack_ids})
            response.raise_for_status()
            acknowledgements = response.json().get("acks", {})
            if all(acknowledgements.get(str(ack_id)) is True for ack_id in ack_ids):
                return True
            await asyncio.sleep(0.25)
        return False

    async def health(self) -> "SplunkHECHealth":
        if not self.config.url:
            return SplunkHECHealth(configured=False, reachable=False, detail="SPLUNK_HEC_URL is unset")
        health_url = self.config.url.replace("/services/collector/event", "/services/collector/health")
        headers = {"Authorization": f"Splunk {self.config.token}"} if self.config.token else {}
        try:
            async with httpx.AsyncClient(verify=self.config.verify_tls, timeout=10) as client:
                response = await client.get(health_url, headers=headers)
            return SplunkHECHealth(
                configured=self.config.enabled,
                reachable=response.is_success,
                status_code=response.status_code,
                detail=response.text[:500],
            )
        except httpx.HTTPError as exc:
            return SplunkHECHealth(configured=self.config.enabled, reachable=False, detail=str(exc))


class SplunkHECHealth(BaseModel):
    configured: bool
    reachable: bool
    status_code: int | None = None
    detail: str


class SplunkHECReceipt(BaseModel):
    status: Literal[
        "not_configured",
        "accepted",
        "accepted_unconfirmed",
        "indexed",
    ]
    events: int
    ack_ids: list[int] = Field(default_factory=list)
    detail: str | None = None
