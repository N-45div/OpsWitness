from opswitness.splunk.governance import SAVED_SEARCH_BY_SCENARIO, SELECTED_MLTK_ALGORITHM


def test_every_live_scenario_has_an_approved_saved_search() -> None:
    assert SAVED_SEARCH_BY_SCENARIO == {
        "deployment_regression": "OpsWitness - Verify Deployment Regression",
        "credential_attack": "OpsWitness - Verify Credential Attack",
        "queue_saturation": "OpsWitness - Verify Queue Saturation",
    }


def test_density_function_is_the_selected_mltk_algorithm() -> None:
    assert SELECTED_MLTK_ALGORITHM == "DensityFunction"
