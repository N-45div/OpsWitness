from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from pydantic import BaseModel, Field

from opswitness.core.event_store import JsonEventStore
from opswitness.core.events import AgentEvent, EventType, RunGraph, SourceTrust
from opswitness.graph.builder import GraphBuilder
from opswitness.graph.store import JsonGraphStore
from opswitness.incidents.models import ApprovalRequest, DeploymentRecord, IncidentBrief, IncidentBriefRequest
from opswitness.incidents.service import IncidentStore, build_incident_brief
from opswitness.integrations.slack import SlackNotifier
from opswitness.integrations.soar import SplunkSOARClient
from opswitness.mcp.normalizer import JsonRpcDirection, MCPTraceNormalizer
from opswitness.mcp.proxy import MCPProxy, MCPProxyConfig
from opswitness.rag.explainer import GraphExplainer
from opswitness.splunk.hec import SplunkHECClient, SplunkHECConfig
from opswitness.splunk.capabilities import (
    SplunkAnomalyRequest,
    run_mcp_preflight,
    run_native_anomaly_investigation,
)
from opswitness.splunk.search import SplunkSearchClient, SplunkSearchConfig
from opswitness.splunk.governance import (
    SAVED_SEARCH_BY_SCENARIO,
    discover_kv_policy,
    persist_model_feedback,
    run_hosted_model_inference,
    verify_with_saved_search,
)


load_dotenv()

ROOT = Path(os.getenv("OPSWITNESS_STORE_DIR", ".opswitness"))
GRAPH_STORE = JsonGraphStore(ROOT / "graphs")
EVENT_STORE = JsonEventStore(ROOT / "events")
INCIDENT_STORE = IncidentStore(ROOT / "incidents")

app = FastAPI(title="OpsWitness", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class MCPTraceEnvelope(BaseModel):
    message: dict | list
    direction: JsonRpcDirection
    run_id: str
    session_id: str
    agent_id: str = "mcp-agent"
    parent_node_id: str | None = None


class MCPProxyEnvelope(BaseModel):
    message: dict | list
    run_id: str | None = None
    session_id: str | None = None
    agent_id: str = "mcp-agent"
    headers: dict[str, str] = Field(default_factory=dict)


class LiveIncidentDrillRequest(BaseModel):
    scenario: Literal["deployment_regression", "credential_attack", "queue_saturation"] = (
        "deployment_regression"
    )
    index: str = "main"


class LiveIncidentDrillStage(BaseModel):
    id: str
    label: str
    status: Literal["completed", "failed", "unavailable"]
    detail: str


class LiveIncidentDrillResult(BaseModel):
    status: Literal["completed", "failed"]
    scenario: str
    scenario_label: str
    run_id: str
    deployment_id: str
    incident_id: str | None = None
    stages: list[LiveIncidentDrillStage] = Field(default_factory=list)
    incident: IncidentBrief | None = None


class LiveIncidentDrillJob(BaseModel):
    job_id: str
    status: Literal["queued", "running", "completed", "failed"]
    result: LiveIncidentDrillResult | None = None


LIVE_DRILL_SCENARIOS = {
    "deployment_regression": {
        "label": "Checkout deployment regression",
        "service": "checkout-api",
        "version": "2.7.1",
        "signal": "error_spike",
        "baseline": 10,
        "current": 420,
        "services": ["checkout-api", "payment-service"],
        "regions": ["us-east-1", "eu-west-1"],
        "title": "Checkout deployment regression",
        "cause": "Checkout release 2.7.1 correlates with a sharp increase in server errors.",
        "action": "Validate and approve a scoped rollback of checkout-api 2.7.1",
    },
    "credential_attack": {
        "label": "Credential-stuffing attack",
        "service": "auth-gateway",
        "version": "security-policy-14",
        "signal": "auth_failures",
        "baseline": 18,
        "current": 970,
        "services": ["auth-gateway", "identity-service"],
        "regions": ["us-east-1", "ap-southeast-1"],
        "title": "Credential-stuffing attack against authentication",
        "cause": "A distributed burst of failed logins and unauthorized responses indicates credential stuffing.",
        "action": "Approve temporary source throttling and force step-up authentication",
    },
    "queue_saturation": {
        "label": "Order queue saturation",
        "service": "order-worker",
        "version": "worker-5.4.0",
        "signal": "queue_saturation",
        "baseline": 35,
        "current": 680,
        "services": ["order-worker", "fulfillment-api"],
        "regions": ["us-west-2"],
        "title": "Order processing queue saturation",
        "cause": "Queue depth and p95 processing latency rose together after worker throughput degraded.",
        "action": "Approve a bounded worker scale-out and inspect the slow consumer group",
    },
}
LIVE_DRILL_JOBS: dict[str, LiveIncidentDrillJob] = {}


def splunk_client() -> SplunkHECClient:
    return SplunkHECClient(
        SplunkHECConfig(
            url=os.getenv("SPLUNK_HEC_URL", ""),
            token=os.getenv("SPLUNK_HEC_TOKEN", ""),
            index=os.getenv("SPLUNK_INDEX", "opswitness"),
            verify_tls=os.getenv("SPLUNK_VERIFY_TLS", "true").lower() != "false",
            ack_mode=os.getenv("SPLUNK_HEC_ACK_MODE", "auto").lower(),
            ack_timeout_seconds=float(os.getenv("SPLUNK_HEC_ACK_TIMEOUT_SECONDS", "10")),
        )
    )


def splunk_search_client() -> SplunkSearchClient:
    verify_tls = os.getenv("SPLUNK_VERIFY_TLS", "true").lower() != "false"
    return SplunkSearchClient(
        SplunkSearchConfig(
            base_url=os.getenv("SPLUNK_BASE_URL", ""),
            auth_token=os.getenv("SPLUNK_AUTH_TOKEN", ""),
            username=os.getenv("SPLUNK_USERNAME", ""),
            password=os.getenv("SPLUNK_PASSWORD", ""),
            verify_tls=verify_tls,
        )
    )


def mcp_proxy() -> MCPProxy:
    return MCPProxy(
        MCPProxyConfig(
            upstream_url=os.getenv("SPLUNK_MCP_URL", ""),
            bearer_token=os.getenv("SPLUNK_MCP_BEARER_TOKEN", ""),
            verify_tls=os.getenv("SPLUNK_VERIFY_TLS", "true").lower() != "false",
        )
    )


def slack_notifier() -> SlackNotifier:
    return SlackNotifier(
        webhook_url=os.getenv("SLACK_WEBHOOK_URL", ""),
        console_url=os.getenv("OPSWITNESS_CONSOLE_URL", "http://127.0.0.1:3000"),
    )


def soar_client() -> SplunkSOARClient:
    return SplunkSOARClient(
        base_url=os.getenv("SPLUNK_SOAR_URL", ""),
        token=os.getenv("SPLUNK_SOAR_TOKEN", ""),
        verify_tls=os.getenv("SPLUNK_VERIFY_TLS", "true").lower() != "false",
    )


def require_evidence_sink() -> SplunkHECClient:
    hec = splunk_client()
    if os.getenv("SPLUNK_REQUIRE_HEC", "true").lower() == "true" and not hec.config.enabled:
        raise HTTPException(
            status_code=503,
            detail="Splunk HEC is required. Set SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN.",
        )
    return hec


async def persist_events(events: list[AgentEvent]) -> dict:
    hec = require_evidence_sink()
    receipt = await hec.send_events(events)
    EVENT_STORE.append(events)
    graphs = GraphBuilder().build(EVENT_STORE.load_all())
    for graph in graphs:
        GRAPH_STORE.save(graph)
    return {
        "accepted": len(events),
        "graphs": len(graphs),
        "splunk_evidence_status": receipt.status,
    }


@app.get("/")
def index() -> dict[str, str]:
    return {"name": "OpsWitness API", "status": "ok"}


@app.get("/health")
def health() -> dict[str, str | int]:
    return {"status": "ok", "events_persisted": len(EVENT_STORE.load_all())}


@app.post("/events")
async def ingest_events(events: list[AgentEvent]) -> dict:
    return await persist_events(events)


@app.post("/mcp/trace")
async def trace_mcp(envelope: MCPTraceEnvelope) -> dict:
    events = MCPTraceNormalizer().normalize(
        envelope.message,
        direction=envelope.direction,
        run_id=envelope.run_id,
        session_id=envelope.session_id,
        agent_id=envelope.agent_id,
        parent_node_id=envelope.parent_node_id,
    )
    return await persist_events(events)


@app.post("/mcp/proxy")
async def proxy_mcp(
    envelope: MCPProxyEnvelope,
    mcp_session_id: str | None = Header(default=None),
    mcp_protocol_version: str | None = Header(default=None),
) -> dict:
    require_evidence_sink()
    forwarded_headers = dict(envelope.headers)
    if mcp_session_id:
        forwarded_headers["mcp-session-id"] = mcp_session_id
    if mcp_protocol_version:
        forwarded_headers["mcp-protocol-version"] = mcp_protocol_version
    try:
        upstream, events = await mcp_proxy().forward(
            envelope.message,
            run_id=envelope.run_id,
            session_id=envelope.session_id,
            agent_id=envelope.agent_id,
            headers=forwarded_headers,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    await persist_events(events)
    return {"upstream_status": upstream.status_code, "response": upstream.body, "events": len(events)}


@app.post("/mcp")
async def proxy_raw_mcp(
    request: Request,
    x_opswitness_run_id: str | None = Header(default=None),
    x_opswitness_session_id: str | None = Header(default=None),
    x_opswitness_agent_id: str = Header(default="mcp-agent"),
    mcp_session_id: str | None = Header(default=None),
    mcp_protocol_version: str | None = Header(default=None),
) -> Response:
    require_evidence_sink()
    try:
        message = await request.json()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Request body must be JSON-RPC JSON") from exc

    forwarded_headers: dict[str, str] = {}
    if mcp_session_id:
        forwarded_headers["mcp-session-id"] = mcp_session_id
    if mcp_protocol_version:
        forwarded_headers["mcp-protocol-version"] = mcp_protocol_version

    try:
        upstream, events = await mcp_proxy().forward(
            message,
            run_id=x_opswitness_run_id,
            session_id=x_opswitness_session_id,
            agent_id=x_opswitness_agent_id,
            headers=forwarded_headers,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    await persist_events(events)
    if "application/json" in upstream.content_type:
        return JSONResponse(
            content=upstream.body,
            status_code=upstream.status_code,
            headers=upstream.headers,
        )
    return Response(
        content=upstream.raw_body,
        status_code=upstream.status_code,
        media_type=upstream.content_type,
        headers=upstream.headers,
    )


@app.get("/splunk/status")
async def splunk_status() -> dict:
    hec = splunk_client()
    return {
        "hec": {
            **(await hec.health()).model_dump(),
            "ack_mode": hec.config.ack_mode,
        },
        "search": await splunk_search_client().health(),
        "mcp_proxy": {
            "configured": mcp_proxy().config.enabled,
            "upstream_url": bool(mcp_proxy().config.upstream_url),
            "preflight_configured": mcp_proxy().config.enabled,
            "native_anomaly_requires_tool": "splunk_run_query",
        },
        "slack": {"configured": slack_notifier().configured},
        "hosted_model": {
            "configured": mcp_proxy().config.enabled,
            "model_name": os.getenv("SPLUNK_HOSTED_MODEL_NAME", "").strip()
            or "splunk-native-anomalydetection",
            "mode": "mltk_model"
            if os.getenv("SPLUNK_HOSTED_MODEL_NAME", "").strip()
            else "splunk_native_analytics",
        },
        "soar": await soar_client().health(),
        "mcp_required_capability": "mcp_tool_execute",
    }


@app.post("/splunk/search")
async def splunk_search(payload: dict) -> dict:
    query = payload.get("query")
    if not isinstance(query, str) or not query.strip():
        raise HTTPException(status_code=400, detail="query is required")
    result = await splunk_search_client().export(query=query, count=int(payload.get("count", 100)))
    return result.model_dump()


@app.post("/splunk/mcp/preflight")
async def splunk_mcp_preflight(payload: dict | None = None) -> dict:
    require_evidence_sink()
    try:
        result, events = await run_mcp_preflight(
            mcp_proxy(),
            run_id=(payload or {}).get("run_id"),
        )
    except (RuntimeError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if events:
        await persist_events(events)
    return result.model_dump()


@app.post("/splunk/anomaly-investigation")
async def splunk_anomaly_investigation(request: SplunkAnomalyRequest) -> dict:
    if request.execute:
        require_evidence_sink()
    try:
        result = await run_native_anomaly_investigation(mcp_proxy(), request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (RuntimeError, httpx.HTTPError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if result.events:
        await persist_events(result.events)
    return result.model_dump()


@app.post("/drills/live-incident")
async def run_live_incident_drill(
    request: LiveIncidentDrillRequest | None = None,
) -> LiveIncidentDrillResult:
    drill = request or LiveIncidentDrillRequest()
    scenario = LIVE_DRILL_SCENARIOS[drill.scenario]
    suffix = uuid4().hex[:10]
    run_id = f"{drill.scenario}-{suffix}"
    deployment_id = f"deploy-{suffix}"
    stages: list[LiveIncidentDrillStage] = []

    def complete(stage_id: str, label: str, detail: str) -> None:
        stages.append(
            LiveIncidentDrillStage(id=stage_id, label=label, status="completed", detail=detail)
        )

    def unavailable(stage_id: str, label: str, detail: str) -> None:
        stages.append(
            LiveIncidentDrillStage(id=stage_id, label=label, status="unavailable", detail=detail)
        )

    def fail(stage_id: str, label: str, detail: str) -> LiveIncidentDrillResult:
        stages.append(LiveIncidentDrillStage(id=stage_id, label=label, status="failed", detail=detail))
        return LiveIncidentDrillResult(
            status="failed",
            scenario=drill.scenario,
            scenario_label=scenario["label"],
            run_id=run_id,
            deployment_id=deployment_id,
            stages=stages,
        )

    try:
        hec = require_evidence_sink()
    except HTTPException as exc:
        return fail("hec", "Splunk HEC evidence sink", str(exc.detail))
    hec_health = await hec.health()
    if not hec_health.configured or not hec_health.reachable:
        return fail("hec", "Splunk HEC evidence sink", hec_health.detail)
    if not mcp_proxy().config.enabled:
        return fail("mcp", "Splunk MCP capability preflight", "Splunk MCP is not configured.")
    if not slack_notifier().configured:
        return fail("slack", "Slack incident notification", "Slack webhook is not configured.")
    complete("hec", "Splunk HEC evidence sink", f"Reachable with acknowledgement mode {hec.config.ack_mode}.")

    try:
        preflight, preflight_events = await run_mcp_preflight(mcp_proxy(), run_id=run_id)
        if preflight_events:
            await persist_events(preflight_events)
    except (RuntimeError, httpx.HTTPError, HTTPException) as exc:
        return fail("mcp", "Splunk MCP capability preflight", str(exc))
    if preflight.status == "unavailable" or not preflight.anomaly_query_supported:
        return fail(
            "mcp",
            "Splunk MCP capability preflight",
            "Splunk MCP did not advertise the required splunk_run_query tool.",
        )
    complete(
        "mcp",
        "Splunk MCP capability preflight",
        f"Discovered {len(preflight.available_tools)} tools; splunk_run_query is available.",
    )

    try:
        anomaly = await run_native_anomaly_investigation(
            mcp_proxy(),
            SplunkAnomalyRequest(
                service=scenario["service"],
                index=drill.index,
                signal=scenario["signal"],
                run_id=run_id,
                execute=True,
            ),
        )
        if anomaly.events:
            await persist_events(anomaly.events)
    except (RuntimeError, ValueError, httpx.HTTPError, HTTPException) as exc:
        return fail("spl", "Native SPL investigation", str(exc))
    if anomaly.status != "executed":
        return fail("spl", "Native SPL investigation", anomaly.detail)
    complete("spl", "Native SPL investigation", anomaly.detail)

    try:
        hosted_model = await run_hosted_model_inference(
            mcp_proxy(),
            scenario_query=anomaly.query,
            run_id=run_id,
        )
        if hosted_model.events:
            await persist_events(hosted_model.events)
    except (RuntimeError, httpx.HTTPError, HTTPException) as exc:
        unavailable("model", "Splunk-hosted model inference", str(exc))
    else:
        if hosted_model.status == "executed":
            await persist_events(
                [
                    AgentEvent(
                        event_type=EventType.model_inference_completed,
                        run_id=run_id,
                        session_id=f"model-{suffix}",
                        agent_id="opswitness-hosted-model",
                        node_id=f"model:{suffix}",
                        source_trust=SourceTrust.trusted,
                        payload={
                            "model_name": os.getenv("SPLUNK_HOSTED_MODEL_NAME")
                            or "splunk-native-anomalydetection",
                            "status": hosted_model.status,
                        },
                    )
                ]
            )
            complete("model", "Splunk-hosted model inference", hosted_model.detail)
        else:
            unavailable("model", "Splunk-hosted model inference", hosted_model.detail)

    try:
        verification = await verify_with_saved_search(
            mcp_proxy(),
            scenario=drill.scenario,
            service=scenario["service"],
            index=drill.index,
            run_id=run_id,
        )
        if verification.events:
            await persist_events(verification.events)
    except (RuntimeError, httpx.HTTPError, HTTPException) as exc:
        unavailable("verification", "Approved saved-search verification", str(exc))
    else:
        if verification.status == "executed":
            await persist_events(
                [
                    AgentEvent(
                        event_type=EventType.saved_search_verified,
                        run_id=run_id,
                        session_id=f"verification-{suffix}",
                        agent_id="opswitness-approved-detection",
                        node_id=f"verification:{suffix}",
                        source_trust=SourceTrust.trusted,
                        payload={
                            "saved_search": SAVED_SEARCH_BY_SCENARIO[drill.scenario],
                            "status": verification.status,
                        },
                    )
                ]
            )
            complete("verification", "Approved saved-search verification", verification.detail)
        else:
            unavailable("verification", "Approved saved-search verification", verification.detail)

    try:
        policy = await discover_kv_policy(
            mcp_proxy(),
            service=scenario["service"],
            run_id=run_id,
        )
        if policy.events:
            await persist_events(policy.events)
    except (RuntimeError, httpx.HTTPError, HTTPException) as exc:
        unavailable("policy", "Splunk KV Store policy", str(exc))
    else:
        if policy.status == "executed":
            await persist_events(
                [
                    AgentEvent(
                        event_type=EventType.policy_evaluated,
                        run_id=run_id,
                        session_id=f"policy-{suffix}",
                        agent_id="opswitness-policy",
                        node_id=f"policy:{suffix}",
                        source_trust=SourceTrust.trusted,
                        payload={
                            "policy_id": "opswitness_service_policy",
                            "service": scenario["service"],
                            "status": policy.status,
                        },
                    )
                ]
            )
            complete("policy", "Splunk KV Store policy", policy.detail)
        else:
            unavailable("policy", "Splunk KV Store policy", policy.detail)

    try:
        deployment = await record_deployment(
            DeploymentRecord(
                deployment_id=deployment_id,
                service=scenario["service"],
                version=scenario["version"],
                run_id=run_id,
                agent_id="live-drill-deployment",
            )
        )
    except (RuntimeError, httpx.HTTPError, HTTPException) as exc:
        return fail("deployment", "Deployment evidence", str(exc))
    complete(
        "deployment",
        "Deployment evidence",
        f"Recorded trusted deployment node {deployment['deployment_node_id']}.",
    )

    graph = get_run(run_id)
    evidence_node_ids = [
        node.id for node in graph.nodes if node.type in {"ToolCall", "ToolResult"}
    ][-4:]
    evidence_node_ids.append(deployment["deployment_node_id"])
    try:
        incident = await create_incident(
            IncidentBriefRequest(
                scenario=drill.scenario,
                run_id=run_id,
                deployment_id=deployment_id,
                service=scenario["service"],
                version=scenario["version"],
                baseline_errors=scenario["baseline"],
                current_errors=scenario["current"],
                affected_services=scenario["services"],
                affected_regions=scenario["regions"],
                evidence_node_ids=evidence_node_ids,
                unsafe_query="search index=* earliest=-7d | table _raw user action",
                title=scenario["title"],
                probable_cause=scenario["cause"],
                proposed_action=scenario["action"],
                agent_id="live-drill-investigator",
                notify_slack=True,
            )
        )
    except (RuntimeError, httpx.HTTPError, HTTPException) as exc:
        return fail("incident", "Evidence-cited incident", str(exc))
    if incident.slack_status != "sent":
        return fail(
            "slack",
            "Slack incident notification",
            incident.slack_detail or f"Slack delivery status was {incident.slack_status}.",
        )
    complete(
        "incident",
        "Evidence-cited incident",
        f"Created {incident.incident_id} with {len(incident.evidence_node_ids)} citations.",
    )
    complete("slack", "Slack incident notification", "Delivered the incident brief to Slack.")

    final_graph = get_run(run_id)
    complete(
        "graph",
        "Causal evidence graph",
        f"Built {len(final_graph.nodes)} nodes and {len(final_graph.edges)} edges; approval is pending.",
    )
    return LiveIncidentDrillResult(
        status="completed",
        scenario=drill.scenario,
        scenario_label=scenario["label"],
        run_id=run_id,
        deployment_id=deployment_id,
        incident_id=incident.incident_id,
        stages=stages,
        incident=incident,
    )


async def execute_live_incident_drill_job(job_id: str, request: LiveIncidentDrillRequest) -> None:
    LIVE_DRILL_JOBS[job_id].status = "running"
    result = await run_live_incident_drill(request)
    LIVE_DRILL_JOBS[job_id].result = result
    LIVE_DRILL_JOBS[job_id].status = result.status


@app.post("/drills/live-incident/jobs")
async def start_live_incident_drill_job(
    background_tasks: BackgroundTasks,
    request: LiveIncidentDrillRequest | None = None,
) -> LiveIncidentDrillJob:
    job_id = f"drill-job-{uuid4().hex[:12]}"
    drill_request = request or LiveIncidentDrillRequest()
    job = LiveIncidentDrillJob(job_id=job_id, status="queued")
    LIVE_DRILL_JOBS[job_id] = job
    background_tasks.add_task(execute_live_incident_drill_job, job_id, drill_request)
    return job


@app.get("/drills/live-incident/jobs/{job_id}")
def get_live_incident_drill_job(job_id: str) -> LiveIncidentDrillJob:
    try:
        return LIVE_DRILL_JOBS[job_id]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="drill job not found") from exc


@app.post("/integrations/deployments")
async def record_deployment(deployment: DeploymentRecord) -> dict:
    run_id = deployment.run_id or f"deploy-{deployment.deployment_id}"
    event = AgentEvent(
        event_type=EventType.deployment_recorded,
        run_id=run_id,
        session_id=f"deployment-{deployment.deployment_id}",
        agent_id=deployment.agent_id,
        node_id=f"deployment:{deployment.deployment_id}",
        timestamp=deployment.deployed_at,
        source_trust=SourceTrust.trusted,
        payload=deployment.model_dump(mode="json") | {"run_id": run_id},
    )
    persisted = await persist_events([event])
    return {"run_id": run_id, "deployment_node_id": event.node_id, **persisted}


@app.post("/incidents")
async def create_incident(request: IncidentBriefRequest) -> IncidentBrief:
    graph = get_run(request.run_id)
    node_ids = {node.id for node in graph.nodes}
    missing = [node_id for node_id in request.evidence_node_ids if node_id not in node_ids]
    if missing:
        raise HTTPException(status_code=400, detail={"missing_evidence_node_ids": missing})

    incident = build_incident_brief(request)
    deployment_node_id = f"deployment:{request.deployment_id}"
    parent_node_id = deployment_node_id if deployment_node_id in node_ids else request.evidence_node_ids[0]
    incident_node_id = f"incident:{incident.incident_id}"
    proposal_node_id = f"proposal:{incident.incident_id}"
    approval_node_id = f"approval:{incident.incident_id}"
    now = datetime.now(timezone.utc)
    events = [
        AgentEvent(
            event_type=EventType.incident_detected,
            run_id=request.run_id,
            session_id=f"incident-{incident.incident_id}",
            agent_id=request.agent_id,
            node_id=incident_node_id,
            parent_node_id=parent_node_id,
            timestamp=now,
            source_trust=SourceTrust.trusted,
            risk_tags=[f"severity:{incident.severity}", "deployment-regression"],
            payload=incident.model_dump(mode="json"),
        ),
        AgentEvent(
            event_type=EventType.remediation_proposed,
            run_id=request.run_id,
            session_id=f"incident-{incident.incident_id}",
            agent_id=request.agent_id,
            node_id=proposal_node_id,
            parent_node_id=incident_node_id,
            timestamp=now,
            source_trust=SourceTrust.unknown,
            risk_tags=["human-approval-required"],
            payload={
                "action": incident.proposed_action,
                "unsafe_query": incident.unsafe_query,
                "safe_query": incident.safe_query,
                "evidence_node_ids": incident.evidence_node_ids,
            },
        ),
        AgentEvent(
            event_type=EventType.human_approval_requested,
            run_id=request.run_id,
            session_id=f"incident-{incident.incident_id}",
            agent_id=request.agent_id,
            node_id=approval_node_id,
            parent_node_id=proposal_node_id,
            timestamp=now,
            source_trust=SourceTrust.trusted,
            payload={"action": incident.proposed_action, "status": "pending"},
        ),
    ]
    await persist_events(events)

    if request.notify_slack:
        status, detail = await slack_notifier().send_incident(incident)
        incident.slack_status = status
        incident.slack_detail = detail
        if status == "sent":
            await persist_events(
                [
                    AgentEvent(
                        event_type=EventType.notification_sent,
                        run_id=request.run_id,
                        session_id=f"incident-{incident.incident_id}",
                        agent_id="slack-integration",
                        node_id=f"notification:{incident.incident_id}:{uuid4().hex[:6]}",
                        parent_node_id=incident_node_id,
                        source_trust=SourceTrust.trusted,
                        payload={"destination": "slack", "status": status},
                    )
                ]
            )
    else:
        incident.slack_status = "not_requested"
    INCIDENT_STORE.save(incident)
    return incident


@app.get("/incidents")
def list_incidents() -> list[IncidentBrief]:
    return INCIDENT_STORE.list()


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: str) -> IncidentBrief:
    try:
        return INCIDENT_STORE.load(incident_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="incident not found") from exc


@app.post("/incidents/{incident_id}/approval")
async def decide_incident(incident_id: str, approval: ApprovalRequest) -> IncidentBrief:
    incident = get_incident(incident_id)
    incident.approval_status = approval.decision
    event_type = (
        EventType.human_approval_approved
        if approval.decision == "approved"
        else EventType.human_approval_rejected
    )
    await persist_events(
        [
            AgentEvent(
                event_type=event_type,
                run_id=incident.run_id,
                session_id=f"incident-{incident.incident_id}",
                agent_id=approval.approver,
                node_id=f"approval-decision:{incident.incident_id}:{uuid4().hex[:6]}",
                parent_node_id=f"approval:{incident.incident_id}",
                source_trust=SourceTrust.trusted,
                payload={
                    "decision": approval.decision,
                    "approver": approval.approver,
                    "reason": approval.reason,
                },
            )
        ]
    )
    try:
        feedback = await persist_model_feedback(
            mcp_proxy(),
            run_id=incident.run_id,
            scenario=incident.scenario,
            accepted=approval.decision == "approved",
            reviewer=approval.approver,
        )
        if feedback.events:
            await persist_events(feedback.events)
    except (RuntimeError, httpx.HTTPError, HTTPException):
        pass
    if approval.decision == "approved":
        container_id = os.getenv("SPLUNK_SOAR_CONTAINER_ID", "").strip()
        playbook = os.getenv(
            f"SPLUNK_SOAR_PLAYBOOK_{incident.scenario.upper()}",
            os.getenv("SPLUNK_SOAR_PLAYBOOK", ""),
        ).strip()
        if not soar_client().configured:
            incident.soar_status = "not_configured"
            incident.soar_detail = "Splunk SOAR is not configured."
        elif not container_id or not playbook:
            incident.soar_status = "not_configured"
            incident.soar_detail = "SOAR container ID or scenario playbook is not configured."
        elif not container_id.isdigit():
            incident.soar_status = "failed"
            incident.soar_detail = "SPLUNK_SOAR_CONTAINER_ID must be an integer."
        else:
            execution = await soar_client().run_playbook(
                playbook=playbook,
                container_id=int(container_id),
            )
            incident.soar_status = execution.status
            incident.soar_detail = execution.detail
            if execution.status == "executed":
                await persist_events(
                    [
                        AgentEvent(
                            event_type=EventType.soar_playbook_executed,
                            run_id=incident.run_id,
                            session_id=f"incident-{incident.incident_id}",
                            agent_id=approval.approver,
                            node_id=f"soar:{incident.incident_id}:{uuid4().hex[:6]}",
                            parent_node_id=f"approval-decision:{incident.incident_id}",
                            source_trust=SourceTrust.trusted,
                            payload={
                                "playbook": playbook,
                                "container_id": int(container_id),
                                "status": execution.status,
                            },
                        )
                    ]
                )
    else:
        incident.soar_status = "not_requested"
    INCIDENT_STORE.save(incident)
    return incident


@app.get("/runs")
def list_runs() -> list[dict]:
    return [
        {
            "run_id": graph.run_id,
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "findings": len(graph.findings),
            "max_severity": _max_severity(graph),
            "started_at": _run_timestamp(graph, first=True),
            "updated_at": _run_timestamp(graph, first=False),
            "agent_id": _run_agent(graph),
            "tool_calls": sum(node.type == "ToolCall" for node in graph.nodes),
        }
        for graph in GRAPH_STORE.list()
    ]


@app.get("/runs/{run_id}")
def get_run(run_id: str) -> RunGraph:
    try:
        return GRAPH_STORE.load(run_id)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="run not found") from exc


@app.get("/runs/{run_id}/explain")
def explain_run(run_id: str) -> dict[str, list[str]]:
    graph = get_run(run_id)
    explainer = GraphExplainer()
    return {"explanations": [explainer.explain_finding(graph, finding) for finding in graph.findings]}


@app.get("/runs/{run_id}/spl")
def run_spl(run_id: str) -> dict[str, str]:
    get_run(run_id)
    index = os.getenv("SPLUNK_INDEX", "*")
    escaped = run_id.replace('"', '\\"')
    return {
        "query": (
            f'index={index} sourcetype="opswitness:event" run_id="{escaped}" '
            "| table _time event_type agent_id node_id parent_node_id source_trust risk_tags payload"
        )
    }


def _max_severity(graph: RunGraph) -> str:
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    if not graph.findings:
        return "none"
    return max(graph.findings, key=lambda finding: order[finding.severity]).severity


def _run_timestamp(graph: RunGraph, *, first: bool) -> str | None:
    timestamps = [str(node.data.get("timestamp")) for node in graph.nodes if node.data.get("timestamp")]
    if not timestamps:
        return None
    return min(timestamps) if first else max(timestamps)


def _run_agent(graph: RunGraph) -> str:
    for node in graph.nodes:
        agent_id = node.data.get("agent_id")
        if isinstance(agent_id, str):
            return agent_id
    return "unknown"
