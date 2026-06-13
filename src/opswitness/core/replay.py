from __future__ import annotations

import argparse
from pathlib import Path

from opswitness.core.io import read_jsonl_events
from opswitness.graph.builder import GraphBuilder
from opswitness.graph.store import JsonGraphStore


def replay(trace_path: Path, output_dir: Path) -> list[Path]:
    events = read_jsonl_events(trace_path)
    graphs = GraphBuilder().build(events)
    store = JsonGraphStore(output_dir)
    return [store.save(graph) for graph in graphs]


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay OpsWitness JSONL traces into graphs.")
    parser.add_argument("trace", type=Path, help="Path to a JSONL trace file")
    parser.add_argument("--out", type=Path, default=Path(".opswitness/graphs"))
    args = parser.parse_args()

    paths = replay(args.trace, args.out)
    for path in paths:
        print(path)


if __name__ == "__main__":
    main()
