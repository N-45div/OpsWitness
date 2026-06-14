import httpx
import pytest

from opswitness.integrations.foundation_sec import FoundationSecClient


@pytest.mark.anyio
async def test_foundation_sec_validates_and_filters_evidence_references(monkeypatch) -> None:
    async def fake_post(self, url, *, headers, json):
        assert headers["Authorization"] == "Bearer secret"
        assert json["temperature"] == 0
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={
                "choices": [
                    {
                        "message": {
                            "content": (
                                '{"classification":"credential stuffing","severity":"critical",'
                                '"probable_cause":"Distributed failed-login burst.",'
                                '"recommended_action":"Block sources after human approval.",'
                                '"confidence":94,"evidence_references":["node-1","invented"]}'
                            )
                        }
                    }
                ]
            },
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    result = await FoundationSecClient(api_key="secret").assess(
        scenario="credential_attack",
        service="auth-gateway",
        signal="auth_failures",
        baseline=18,
        current=970,
        evidence_references=["node-1"],
    )

    assert result.status == "executed"
    assert result.assessment
    assert result.assessment.evidence_references == ["node-1"]


@pytest.mark.anyio
async def test_foundation_sec_fails_closed_on_unstructured_response(monkeypatch) -> None:
    async def fake_post(self, url, *, headers, json):
        return httpx.Response(
            200,
            request=httpx.Request("POST", url),
            json={"choices": [{"message": {"content": "not structured"}}]},
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
    result = await FoundationSecClient(api_key="secret").assess(
        scenario="credential_attack",
        service="auth-gateway",
        signal="auth_failures",
        baseline=18,
        current=970,
        evidence_references=["node-1"],
    )

    assert result.status == "unavailable"
    assert result.assessment is None


@pytest.mark.anyio
async def test_foundation_sec_is_unavailable_without_api_key() -> None:
    result = await FoundationSecClient(api_key="").assess(
        scenario="credential_attack",
        service="auth-gateway",
        signal="auth_failures",
        baseline=18,
        current=970,
        evidence_references=["node-1"],
    )

    assert result.status == "unavailable"
