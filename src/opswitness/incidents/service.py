from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from opswitness.incidents.models import IncidentBrief, IncidentBriefRequest


class IncidentStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, incident: IncidentBrief) -> None:
        incident.updated_at = datetime.now(timezone.utc)
        (self.root / f"{incident.incident_id}.json").write_text(
            incident.model_dump_json(indent=2), encoding="utf-8"
        )

    def load(self, incident_id: str) -> IncidentBrief:
        path = self.root / f"{incident_id}.json"
        return IncidentBrief.model_validate_json(path.read_text(encoding="utf-8"))

    def list(self) -> list[IncidentBrief]:
        return [
            IncidentBrief.model_validate_json(path.read_text(encoding="utf-8"))
            for path in sorted(self.root.glob("*.json"), reverse=True)
        ]


def build_incident_brief(request: IncidentBriefRequest) -> IncidentBrief:
    multiplier = round(request.current_errors / max(request.baseline_errors, 1), 1)
    confidence = min(98, 55 + min(30, int(multiplier * 5)) + min(13, len(request.evidence_node_ids) * 3))
    severity = _severity(multiplier, request.current_errors)
    safe_query = rewrite_safe_query(request.unsafe_query, request.service) if request.unsafe_query else None
    return IncidentBrief(
        incident_id=f"inc-{uuid4().hex[:10]}",
        run_id=request.run_id,
        deployment_id=request.deployment_id,
        scenario=request.scenario,
        title=request.title or f"{request.service} deployment regression",
        severity=severity,
        probable_cause=request.probable_cause
        or (
            f"Deployment {request.deployment_id} of {request.service} {request.version} "
            f"correlates with a {multiplier}x increase in errors."
        ),
        confidence=confidence,
        baseline_errors=request.baseline_errors,
        current_errors=request.current_errors,
        error_multiplier=multiplier,
        affected_services=request.affected_services or [request.service],
        affected_regions=request.affected_regions,
        evidence_node_ids=request.evidence_node_ids,
        unsafe_query=request.unsafe_query,
        safe_query=safe_query,
        proposed_action=request.proposed_action,
    )


def rewrite_safe_query(query: str, service: str) -> str:
    scoped = re.sub(r"\bindex\s*=\s*\*", "index=main", query, flags=re.IGNORECASE)
    scoped = re.sub(r"earliest\s*=\s*-\d+\s*(d|w|mon|y)\b", "earliest=-30m", scoped, flags=re.IGNORECASE)
    scoped = re.sub(r"\|\s*(table|fields)\s+_raw\b[^|]*", "", scoped, flags=re.IGNORECASE)
    if not re.search(rf"\bservice\s*=\s*{re.escape(service)}\b", scoped, flags=re.IGNORECASE):
        scoped = re.sub(r"^\s*search\s+", f"search service={service} ", scoped, count=1, flags=re.IGNORECASE)
    scoped = scoped.strip()
    if "| stats" not in scoped.lower():
        scoped += " | stats count by action region version"
    return scoped


def _severity(multiplier: float, current_errors: int) -> str:
    if multiplier >= 10 or current_errors >= 1000:
        return "critical"
    if multiplier >= 5 or current_errors >= 300:
        return "high"
    if multiplier >= 2 or current_errors >= 100:
        return "medium"
    return "low"
