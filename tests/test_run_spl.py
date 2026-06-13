from fastapi.testclient import TestClient

import opswitness.api.app as api_module
from opswitness.core.events import GraphNode, RunGraph
from opswitness.graph.store import JsonGraphStore


def test_run_spl_uses_wildcard_when_runtime_index_is_unknown(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("SPLUNK_INDEX", raising=False)
    graph_store = JsonGraphStore(tmp_path)
    monkeypatch.setattr(api_module, "GRAPH_STORE", graph_store)
    graph_store.save(
        RunGraph(
            run_id="run-spl-test",
            nodes=[GraphNode(id="node-1", type="Run", label="test")],
            edges=[],
        )
    )

    response = TestClient(api_module.app).get("/runs/run-spl-test/spl")

    assert response.status_code == 200
    assert response.json()["query"].startswith('index=* sourcetype="opswitness:event"')
