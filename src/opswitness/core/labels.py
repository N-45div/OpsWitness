from __future__ import annotations

from opswitness.core.events import AgentEvent, EventType


NODE_TYPE_BY_EVENT = {
    EventType.run_started: "Run",
    EventType.prompt_received: "Prompt",
    EventType.context_retrieved: "ContextChunk",
    EventType.mcp_tool_available: "MCPTool",
    EventType.mcp_tool_selected: "ToolDecision",
    EventType.mcp_tool_called: "ToolCall",
    EventType.splunk_search_generated: "SplunkSearch",
    EventType.splunk_search_executed: "SplunkResult",
    EventType.saved_search_verified: "SavedSearchVerification",
    EventType.model_inference_completed: "ModelInference",
    EventType.policy_evaluated: "PolicyDecision",
    EventType.human_approval_requested: "Approval",
    EventType.human_approval_approved: "ApprovalDecision",
    EventType.human_approval_rejected: "ApprovalDecision",
    EventType.deployment_recorded: "Deployment",
    EventType.incident_detected: "Incident",
    EventType.remediation_proposed: "RemediationProposal",
    EventType.notification_sent: "Notification",
    EventType.soar_playbook_executed: "SOARExecution",
    EventType.run_completed: "RunCompletion",
}

EDGE_BY_EVENT = {
    EventType.prompt_received: ("STARTED_WITH", "started with"),
    EventType.context_retrieved: ("RETRIEVED", "retrieved"),
    EventType.mcp_tool_available: ("EXPOSED_TOOL", "exposed tool"),
    EventType.mcp_tool_selected: ("SELECTED_TOOL", "selected"),
    EventType.mcp_tool_called: ("CALLED", "called"),
    EventType.splunk_search_generated: ("GENERATED_SEARCH", "generated search"),
    EventType.splunk_search_executed: ("EXECUTED_SEARCH", "executed"),
    EventType.policy_evaluated: ("TRIGGERED_POLICY", "triggered policy"),
    EventType.human_approval_requested: ("REQUESTED_APPROVAL", "requested approval"),
    EventType.human_approval_approved: ("APPROVED", "approved"),
    EventType.human_approval_rejected: ("REJECTED", "rejected"),
    EventType.deployment_recorded: ("DEPLOYED", "deployed"),
    EventType.incident_detected: ("TRIGGERED_INCIDENT", "triggered incident"),
    EventType.remediation_proposed: ("PROPOSED_REMEDIATION", "proposed remediation"),
    EventType.notification_sent: ("NOTIFIED", "notified"),
    EventType.run_completed: ("COMPLETED", "completed"),
}


def event_label(event: AgentEvent) -> str:
    payload = event.payload
    if event.event_type == EventType.run_started:
        return payload.get("goal", event.run_id)
    if event.event_type == EventType.prompt_received:
        return payload.get("prompt", "prompt")[:80]
    if event.event_type == EventType.context_retrieved:
        return payload.get("source", payload.get("content", "context"))[:80]
    if event.event_type == EventType.mcp_tool_available:
        return payload.get("tool_name", "tool")
    if event.event_type == EventType.mcp_tool_selected:
        return payload.get("tool_name", "tool decision")
    if event.event_type == EventType.mcp_tool_called:
        return payload.get("tool_name", "tool call")
    if event.event_type == EventType.splunk_search_generated:
        return payload.get("query", "splunk search")[:80]
    if event.event_type == EventType.splunk_search_executed:
        return payload.get("status", "search result")
    if event.event_type == EventType.saved_search_verified:
        return payload.get("saved_search", "saved search verification")
    if event.event_type == EventType.model_inference_completed:
        return payload.get("model_name", "hosted model inference")
    if event.event_type == EventType.policy_evaluated:
        return payload.get("policy_id", "policy")
    if event.event_type == EventType.human_approval_requested:
        return payload.get("action", "approval")
    if event.event_type in {EventType.human_approval_approved, EventType.human_approval_rejected}:
        return payload.get("decision", "approval decision")
    if event.event_type == EventType.deployment_recorded:
        return f"{payload.get('service', 'service')} {payload.get('version', '')}".strip()
    if event.event_type == EventType.incident_detected:
        return payload.get("title", "incident")
    if event.event_type == EventType.remediation_proposed:
        return payload.get("action", "remediation")
    if event.event_type == EventType.notification_sent:
        return payload.get("destination", "notification")
    if event.event_type == EventType.soar_playbook_executed:
        return payload.get("playbook", "SOAR playbook")
    return event.event_type.value
