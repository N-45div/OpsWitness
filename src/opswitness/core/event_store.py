from __future__ import annotations

from pathlib import Path

from opswitness.core.events import AgentEvent
from opswitness.core.io import read_jsonl_events, write_jsonl_events


class JsonEventStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def append(self, events: list[AgentEvent]) -> None:
        by_run: dict[str, list[AgentEvent]] = {}
        for event in events:
            by_run.setdefault(event.run_id, []).append(event)
        for run_id, new_events in by_run.items():
            existing = self.load_run(run_id)
            deduplicated = {event.node_id: event for event in existing}
            deduplicated.update({event.node_id: event for event in new_events})
            ordered = sorted(deduplicated.values(), key=lambda event: event.timestamp)
            write_jsonl_events(self.root / f"{run_id}.events.jsonl", ordered)

    def load_run(self, run_id: str) -> list[AgentEvent]:
        path = self.root / f"{run_id}.events.jsonl"
        if not path.exists():
            return []
        return read_jsonl_events(path)

    def load_all(self) -> list[AgentEvent]:
        events: list[AgentEvent] = []
        for path in sorted(self.root.glob("*.events.jsonl")):
            events.extend(read_jsonl_events(path))
        return events

