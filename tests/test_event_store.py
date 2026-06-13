from pathlib import Path

from opswitness.core.event_store import JsonEventStore
from opswitness.core.events import AgentEvent, EventType


def test_event_store_persists_and_deduplicates_nodes(tmp_path: Path) -> None:
    store = JsonEventStore(tmp_path)
    event = AgentEvent(
        event_type=EventType.run_started,
        run_id="run-persisted",
        session_id="session-persisted",
        agent_id="agent-persisted",
        node_id="node-1",
    )

    store.append([event])
    store.append([event])

    assert len(store.load_all()) == 1
    assert store.load_run("run-persisted")[0].node_id == "node-1"
