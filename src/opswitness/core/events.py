from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class SourceTrust(StrEnum):
    trusted = "trusted"
    untrusted = "untrusted"
    unknown = "unknown"


class EventType(StrEnum):
    run_started = "agent.run.started"
    prompt_received = "agent.prompt.received"
    context_retrieved = "agent.context.retrieved"
    mcp_tool_available = "mcp.tool.available"
    mcp_tool_selected = "mcp.tool.selected"
    mcp_tool_called = "mcp.tool.called"
    splunk_search_generated = "splunk.search.generated"
    splunk_search_executed = "splunk.search.executed"
    saved_search_verified = "splunk.saved_search.verified"
    model_inference_completed = "model.inference.completed"
    policy_evaluated = "policy.evaluated"
    human_approval_requested = "human.approval.requested"
    human_approval_approved = "human.approval.approved"
    human_approval_rejected = "human.approval.rejected"
    deployment_recorded = "deployment.recorded"
    incident_detected = "incident.detected"
    remediation_proposed = "remediation.proposed"
    notification_sent = "notification.sent"
    soar_playbook_executed = "soar.playbook.executed"
    run_completed = "agent.run.completed"


class AgentEvent(BaseModel):
    event_type: EventType
    run_id: str
    session_id: str
    agent_id: str
    node_id: str
    parent_node_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_trust: SourceTrust = SourceTrust.unknown
    risk_tags: list[str] = Field(default_factory=list)
    payload: dict[str, Any] = Field(default_factory=dict)

    def splunk_event(self, index: str) -> dict[str, Any]:
        return {
            "time": self.timestamp.timestamp(),
            "index": index,
            "sourcetype": "opswitness:event",
            "event": self.model_dump(mode="json"),
        }


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    trust: SourceTrust = SourceTrust.unknown
    risk_tags: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    type: str
    label: str
    risk_tags: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    run_id: str
    severity: Literal["low", "medium", "high", "critical"]
    title: str
    summary: str
    risk_tags: list[str]
    path: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommendation: str


class RunGraph(BaseModel):
    run_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    findings: list[Finding] = Field(default_factory=list)
