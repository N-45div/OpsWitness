import pytest

from opswitness.integrations.soar import SplunkSOARClient


@pytest.mark.anyio
async def test_soar_fails_closed_when_not_configured() -> None:
    client = SplunkSOARClient(base_url="", token="")

    health = await client.health()
    execution = await client.run_playbook(playbook="contain_attack", container_id=42)

    assert health["configured"] is False
    assert execution.status == "unavailable"
