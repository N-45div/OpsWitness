from __future__ import annotations

import json
from pathlib import Path

from opswitness.core.events import AgentEvent


def read_jsonl_events(path: Path) -> list[AgentEvent]:
    events: list[AgentEvent] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            events.append(AgentEvent.model_validate(json.loads(line)))
        except Exception as exc:  # pragma: no cover - kept explicit for CLI diagnostics
            raise ValueError(f"Invalid event on {path}:{line_number}: {exc}") from exc
    return events


def write_jsonl_events(path: Path, events: list[AgentEvent]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "\n".join(event.model_dump_json() for event in events)
    path.write_text(payload + "\n", encoding="utf-8")

