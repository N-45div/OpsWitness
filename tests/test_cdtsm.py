import httpx
import pytest

from opswitness.integrations.cdtsm import CDTSMClient


@pytest.mark.anyio
async def test_cdtsm_returns_validated_forecast(monkeypatch) -> None:
    async def fake_post(self, url, *, params, headers, json):
        assert headers["Authorization"] == "Bearer secret"
        assert params["horizon"] == 2
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "request_id": "test",
                "model": "CDTSM",
                "horizon": 2,
                "predictions": [
                    {
                        "mean": [20, 30],
                        "quantiles": {"p5": [10, 15], "p95": [40, 60]},
                    }
                ],
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    result = await CDTSMClient(endpoint="http://cdtsm", auth_token="secret").forecast(
        coarse_context=[1, 2, 3, 4, 5, 6, 7, 8],
        fine_context=[2, 3, 4, 5, 6, 7, 8, 9],
        horizon=2,
    )

    assert result.status == "executed"
    assert result.predicted_peak == 30
    assert result.upper == [40, 60]


@pytest.mark.anyio
async def test_cdtsm_rejects_short_context() -> None:
    result = await CDTSMClient(endpoint="http://cdtsm", auth_token="secret").forecast(
        coarse_context=[1, 2],
        fine_context=[1, 2],
    )

    assert result.status == "unavailable"


@pytest.mark.anyio
async def test_cdtsm_is_unavailable_without_configuration() -> None:
    result = await CDTSMClient(endpoint="", auth_token="").forecast(
        coarse_context=[1, 2, 3, 4, 5, 6, 7, 8],
        fine_context=[2, 3, 4, 5, 6, 7, 8, 9],
    )

    assert result.status == "unavailable"
