from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import BaseModel


@dataclass(frozen=True)
class SplunkSearchConfig:
    base_url: str
    auth_token: str = ""
    username: str = ""
    password: str = ""
    verify_tls: bool = True

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and (self.auth_token or (self.username and self.password)))


class SplunkSearchResult(BaseModel):
    query: str
    rows: list[dict[str, Any]]
    raw: str


class SplunkSearchClient:
    def __init__(self, config: SplunkSearchConfig) -> None:
        self.config = config

    async def export(self, query: str, count: int = 100) -> SplunkSearchResult:
        if not self.config.enabled:
            raise RuntimeError("Splunk search is not configured")
        url = self.config.base_url.rstrip("/") + "/services/search/v2/jobs/export"
        data = {"search": query, "output_mode": "json", "count": str(count)}
        headers = self._headers()
        auth = None
        if self.config.username and self.config.password and not self.config.auth_token:
            auth = (self.config.username, self.config.password)
        async with httpx.AsyncClient(verify=self.config.verify_tls, timeout=30) as client:
            response = await client.post(url, data=data, headers=headers, auth=auth)
        response.raise_for_status()
        rows: list[dict[str, Any]] = []
        for line in response.text.splitlines():
            if not line.strip():
                continue
            try:
                rows.append(httpx.Response(200, content=line).json())
            except ValueError:
                rows.append({"raw": line})
        return SplunkSearchResult(query=query, rows=rows, raw=response.text)

    async def health(self) -> dict[str, Any]:
        if not self.config.base_url:
            return {"configured": False, "reachable": False, "detail": "SPLUNK_BASE_URL is unset"}
        url = self.config.base_url.rstrip("/") + "/services/server/info"
        try:
            async with httpx.AsyncClient(verify=self.config.verify_tls, timeout=10) as client:
                response = await client.get(url, headers=self._headers(), auth=self._auth())
            return {
                "configured": self.config.enabled,
                "reachable": response.is_success,
                "status_code": response.status_code,
                "detail": response.text[:500],
            }
        except httpx.HTTPError as exc:
            return {"configured": self.config.enabled, "reachable": False, "detail": str(exc)}

    def _headers(self) -> dict[str, str]:
        if self.config.auth_token:
            return {"Authorization": f"Bearer {self.config.auth_token}"}
        return {}

    def _auth(self) -> tuple[str, str] | None:
        if self.config.username and self.config.password and not self.config.auth_token:
            return (self.config.username, self.config.password)
        return None
