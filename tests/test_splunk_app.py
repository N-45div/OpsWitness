from pathlib import Path


APP_ROOT = Path("splunk/opswitness")


def test_splunk_app_contains_governance_assets() -> None:
    required = {
        "default/app.conf",
        "default/collections.conf",
        "default/savedsearches.conf",
        "default/transforms.conf",
        "default/data/ui/views/opswitness_evidence_operations.xml",
        "lookups/opswitness_service_policy_seed.csv",
        "lookups/opswitness_response_playbooks_seed.csv",
        "metadata/default.meta",
    }

    assert {str(path.relative_to(APP_ROOT)) for path in APP_ROOT.rglob("*") if path.is_file()} >= required


def test_splunk_app_defines_all_governance_collections_and_saved_searches() -> None:
    collections = (APP_ROOT / "default/collections.conf").read_text(encoding="utf-8")
    saved_searches = (APP_ROOT / "default/savedsearches.conf").read_text(encoding="utf-8")

    assert "[opswitness_service_policy]" in collections
    assert "[opswitness_response_playbooks]" in collections
    assert "[opswitness_model_feedback]" in collections
    assert "[OpsWitness - Verify Deployment Regression]" in saved_searches
    assert "[OpsWitness - Verify Credential Attack]" in saved_searches
    assert "[OpsWitness - Verify Queue Saturation]" in saved_searches
