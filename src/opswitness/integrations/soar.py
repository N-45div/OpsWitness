from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import httpx
from pydantic import BaseModel


class SOARExecution(BaseModel):
    status: Literal["executed", "unavailable", "failed"]
    detail: str
    response: Any | None = None


@dataclass(frozen=True)
class SplunkSOARClient:
    base_url: str
    token: str
    verify_tls: bool = True

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.token)

    async def health(self) -> dict[str, Any]:
        if not self.configured:
            return {"configured": False, "reachable": False, "detail": "Splunk SOAR is not configured."}
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=15) as client:
                response = await client.get(
                    self.base_url.rstrip("/") + "/rest/system_info",
                    headers=self._headers(),
                )
            return {
                "configured": True,
                "reachable": response.is_success,
                "status_code": response.status_code,
                "detail": response.text[:500],
            }
        except httpx.HTTPError as exc:
            return {"configured": True, "reachable": False, "detail": str(exc)}

    async def run_playbook(
        self,
        *,
        playbook: str,
        container_id: int,
        scope: str = "all",
    ) -> SOARExecution:
        if not self.configured:
            return SOARExecution(status="unavailable", detail="Splunk SOAR is not configured.")
        payload = {"playbook_id": playbook, "container_id": container_id, "scope": scope, "run": True}
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=30) as client:
                response = await client.post(
                    self.base_url.rstrip("/") + "/rest/playbook_run",
                    headers=self._headers(),
                    json=payload,
                )
            response.raise_for_status()
            return SOARExecution(status="executed", detail="Splunk SOAR playbook started.", response=response.json())
        except (httpx.HTTPError, ValueError) as exc:
            return SOARExecution(status="failed", detail=str(exc))

    def _headers(self) -> dict[str, str]:
        return {"ph-auth-token": self.token, "content-type": "application/json"}
