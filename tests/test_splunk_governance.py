from opswitness.splunk.governance import SAVED_SEARCH_BY_SCENARIO


def test_every_live_scenario_has_an_approved_saved_search() -> None:
    assert SAVED_SEARCH_BY_SCENARIO == {
        "deployment_regression": "OpsWitness - Verify Deployment Regression",
        "credential_attack": "OpsWitness - Verify Credential Attack",
        "queue_saturation": "OpsWitness - Verify Queue Saturation",
    }
