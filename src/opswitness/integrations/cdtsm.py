from __future__ import annotations

import os
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field, ValidationError


class CDTSMForecast(BaseModel):
    status: Literal["executed", "unavailable"]
    detail: str
    model: str = "CDTSM"
    horizon: int = 0
    mean: list[float] = Field(default_factory=list)
    lower: list[float] = Field(default_factory=list)
    upper: list[float] = Field(default_factory=list)
    predicted_peak: float | None = None


class CDTSMClient:
    def __init__(
        self,
        *,
        endpoint: str | None = None,
        auth_token: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.endpoint = (
            endpoint
            if endpoint is not None
            else os.getenv("CDTSM_ENDPOINT", "").strip().rstrip("/")
        )
        self.auth_token = auth_token if auth_token is not None else _load_auth_token()
        self.timeout = timeout or float(os.getenv("CDTSM_TIMEOUT_SECONDS", "120"))

    @property
    def configured(self) -> bool:
        return bool(self.endpoint and self.auth_token)

    async def health(self) -> dict:
        if not self.configured:
            return {"configured": False, "ready": False, "detail": "CDTSM is not configured."}
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self.endpoint}/ready")
            body = response.json()
            ready = response.status_code == 200 and body.get("status") == "ready"
            return {
                "configured": True,
                "ready": ready,
                "detail": "CDTSM is ready." if ready else body.get("message", "CDTSM is loading."),
            }
        except (httpx.HTTPError, ValueError) as exc:
            return {"configured": True, "ready": False, "detail": f"CDTSM health failed: {type(exc).__name__}."}

    async def forecast(
        self,
        *,
        coarse_context: list[float],
        fine_context: list[float],
        horizon: int = 16,
    ) -> CDTSMForecast:
        if not self.configured:
            return CDTSMForecast(status="unavailable", detail="CDTSM is not configured.")
        if len(coarse_context) < 8 or len(fine_context) < 8:
            return CDTSMForecast(
                status="unavailable",
                detail="CDTSM requires at least eight coarse and fine context points.",
            )
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.endpoint}/cdtsm/v1/ai/infer",
                    params={"horizon": horizon},
                    headers={
                        "Authorization": f"Bearer {self.auth_token}",
                        "request_id": f"opswitness-{uuid4().hex[:12]}",
                    },
                    json={
                        "payload": [
                            {
                                "coarse_ctx": coarse_context,
                                "fine_ctx": fine_context,
                            }
                        ],
                        "model": "CDTSM",
                        "metadata": {"quantiles": ["mean", "p5", "p95"]},
                    },
                )
            response.raise_for_status()
            body = response.json()
            prediction = body["predictions"][0]
            mean = [float(value) for value in prediction["mean"]]
            lower = [float(value) for value in prediction["quantiles"]["p5"]]
            upper = [float(value) for value in prediction["quantiles"]["p95"]]
        except (httpx.HTTPError, KeyError, IndexError, TypeError, ValueError, ValidationError) as exc:
            return CDTSMForecast(
                status="unavailable",
                detail=f"CDTSM inference failed: {type(exc).__name__}.",
            )
        return CDTSMForecast(
            status="executed",
            detail="Cisco Deep Time Series Model produced a zero-shot forecast.",
            model=str(body.get("model", "CDTSM")),
            horizon=int(body.get("horizon", horizon)),
            mean=mean,
            lower=lower,
            upper=upper,
            predicted_peak=max(mean) if mean else None,
        )


def _load_auth_token() -> str:
    token = os.getenv("CDTSM_AUTH_TOKEN", "").strip()
    if token:
        return token
    env_file = os.getenv("CDTSM_ENV_FILE", "").strip()
    if not env_file:
        return ""
    try:
        for line in Path(env_file).read_text(encoding="utf-8").splitlines():
            if line.startswith("CDTSM_AUTH_TOKEN="):
                return line.partition("=")[2].strip()
    except OSError:
        return ""
    return ""
