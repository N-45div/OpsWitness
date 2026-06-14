from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field


class DeploymentRecord(BaseModel):
    deployment_id: str
    service: str
    version: str
    environment: str = "production"
    commit_sha: str | None = None
    deployed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    run_id: str | None = None
    agent_id: str = "deployment-integration"


class IncidentBriefRequest(BaseModel):
    run_id: str
    deployment_id: str
    service: str
    version: str
    baseline_errors: int = Field(ge=0)
    current_errors: int = Field(ge=0)
    affected_services: list[str] = Field(default_factory=list)
    affected_regions: list[str] = Field(default_factory=list)
    evidence_node_ids: list[str] = Field(min_length=1)
    unsafe_query: str | None = None
    title: str | None = None
    probable_cause: str | None = None
    proposed_action: str = "Run a scoped follow-up investigation"
    agent_id: str = "incident-investigator"
    notify_slack: bool = True


class IncidentBrief(BaseModel):
    incident_id: str
    run_id: str
    deployment_id: str
    title: str
    severity: Literal["low", "medium", "high", "critical"]
    probable_cause: str
    confidence: int = Field(ge=0, le=100)
    baseline_errors: int
    current_errors: int
    error_multiplier: float
    affected_services: list[str]
    affected_regions: list[str]
    evidence_node_ids: list[str]
    unsafe_query: str | None = None
    safe_query: str | None = None
    proposed_action: str
    approval_status: Literal["pending", "approved", "rejected"] = "pending"
    slack_status: Literal["not_configured", "sent", "failed", "not_requested"] = "not_requested"
    slack_detail: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ApprovalRequest(BaseModel):
    decision: Literal["approved", "rejected"]
    approver: str
    reason: str | None = None
