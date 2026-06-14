"use client";

import {
  AlertTriangle,
  Check,
  Clipboard,
  Database,
  GitBranch,
  LoaderCircle,
  MessageSquare,
  Network,
  Play,
  RefreshCw,
  ShieldCheck,
  Timer,
  X
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  apiBase,
  decideIncident,
  getRun,
  getRunSpl,
  listIncidents,
  listRuns,
  runLiveIncidentDrill,
  splunkStatus
} from "./api";
import { GraphCanvas } from "./GraphCanvas";
import type {
  GraphNode,
  IncidentBrief,
  LiveIncidentDrillResult,
  LiveIncidentDrillScenario,
  RunGraph,
  RunSummary,
  SplunkStatus
} from "./types";

const severityRank = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
const drillScenarios: { value: LiveIncidentDrillScenario; label: string }[] = [
  { value: "deployment_regression", label: "Checkout regression" },
  { value: "credential_attack", label: "Credential attack" },
  { value: "queue_saturation", label: "Queue saturation" }
];

export function OpsWitnessConsole() {
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [activeRun, setActiveRun] = useState<RunGraph | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [status, setStatus] = useState<SplunkStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"graph" | "timeline">("graph");
  const [splQuery, setSplQuery] = useState("");
  const [copied, setCopied] = useState(false);
  const [incidents, setIncidents] = useState<IncidentBrief[]>([]);
  const [drill, setDrill] = useState<LiveIncidentDrillResult | null>(null);
  const [drillRunning, setDrillRunning] = useState(false);
  const [drillScenario, setDrillScenario] =
    useState<LiveIncidentDrillScenario>("deployment_regression");

  const loadRun = useCallback(async (runId: string) => {
    const [graph, spl] = await Promise.all([getRun(runId), getRunSpl(runId)]);
    setActiveRun(graph);
    setSplQuery(spl.query);
    setSelectedNode(null);
  }, []);

  const refresh = useCallback(async (preferredRunId?: string) => {
    setLoading(true);
    setError(null);
    try {
      const [nextRuns, nextStatus, nextIncidents] = await Promise.all([
        listRuns(),
        splunkStatus(),
        listIncidents()
      ]);
      setStatus(nextStatus);
      setIncidents(nextIncidents);
      const sorted = [...nextRuns].sort(
        (a, b) => severityRank[b.max_severity] - severityRank[a.max_severity]
      );
      setRuns(sorted);
      const runId = preferredRunId ?? sorted[0]?.run_id;
      if (runId) await loadRun(runId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown API error");
    } finally {
      setLoading(false);
    }
  }, [loadRun]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const activeSummary = useMemo(
    () => runs.find((run) => run.run_id === activeRun?.run_id),
    [runs, activeRun?.run_id]
  );
  const activeIncident = useMemo(
    () => incidents.find((incident) => incident.run_id === activeRun?.run_id) ?? null,
    [incidents, activeRun?.run_id]
  );

  async function approveIncident(decision: "approved" | "rejected") {
    if (!activeIncident) return;
    setLoading(true);
    setError(null);
    try {
      await decideIncident(activeIncident.incident_id, decision);
      await refresh(activeIncident.run_id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not record approval decision");
    } finally {
      setLoading(false);
    }
  }

  async function startLiveIncidentDrill() {
    setDrillRunning(true);
    setDrill(null);
    setError(null);
    try {
      const result = await runLiveIncidentDrill(drillScenario);
      setDrill(result);
      await refresh(result.run_id);
    } catch (err) {
      await refresh();
      setError(
        err instanceof Error
          ? `Drill connection interrupted: ${err.message}. Existing completed runs were refreshed.`
          : "Could not run the live incident drill"
      );
    } finally {
      setDrillRunning(false);
    }
  }

  return (
    <main className="appShell">
      <aside className="sideRail">
        <div className="brandBlock">
          <div className="brandMark">
            <GitBranch size={20} />
          </div>
          <div>
            <h1>OpsWitness</h1>
            <p>Evidence-first incident room.</p>
          </div>
        </div>

        <div className="metricGrid">
          <Metric icon={<Database size={16} />} label="Runs" value={runs.length.toString()} />
          <Metric
            icon={<AlertTriangle size={16} />}
            label="Findings"
            value={runs.reduce((total, run) => total + run.findings, 0).toString()}
          />
          <Metric
            icon={<Network size={16} />}
            label="Tool calls"
            value={runs.reduce((total, run) => total + run.tool_calls, 0).toString()}
          />
        </div>

        <section className="statusPanel">
          <h2>Splunk</h2>
          <StatusRow label="HEC" ok={status ? status.hec.configured && status.hec.reachable : null} />
          <StatusRow
            label="Direct REST (optional)"
            ok={status ? status.search.configured && status.search.reachable : null}
          />
          <StatusRow label="MCP Proxy" ok={status ? status.mcp_proxy.configured : null} />
          <StatusRow
            label="Preflight endpoint"
            ok={status ? status.mcp_proxy.preflight_configured : null}
          />
          <StatusRow label="Slack" ok={status ? status.slack.configured : null} />
          <p>HEC acknowledgement mode: {status?.hec.ack_mode ?? "unknown"}</p>
          <p>
            Native anomaly requires live tool:{" "}
            {status?.mcp_proxy.native_anomaly_requires_tool ?? "splunk_run_query"}
          </p>
          <p>Required MCP capability: {status?.mcp_required_capability ?? "mcp_tool_execute"}</p>
        </section>

        <section className="runSection">
          <div className="sectionHeader">
            <h2>Runs</h2>
            <button aria-label="Refresh runs" className="iconButton" onClick={() => refresh()}>
              <RefreshCw size={16} />
            </button>
          </div>
          <div className="runList">
            {runs.map((run) => (
              <button
                className={`runRow ${run.run_id === activeRun?.run_id ? "active" : ""}`}
                key={run.run_id}
                onClick={() => loadRun(run.run_id)}
              >
                <span>
                  <strong>{run.run_id}</strong>
                  <small>
                    {run.agent_id} / {run.tool_calls} tool calls
                  </small>
                </span>
                <SeverityBadge severity={run.max_severity} />
              </button>
            ))}
            {!runs.length && <p className="emptyText">No traces loaded.</p>}
          </div>
        </section>
      </aside>

      <section className="workbench">
        <header className="topbar">
          <div>
            <strong>{activeRun?.run_id ?? "No run selected"}</strong>
            <span>
              {activeSummary
                ? `${activeSummary.agent_id} / ${activeSummary.nodes} evidence nodes / ${activeSummary.findings} findings`
                : apiBase()}
            </span>
          </div>
          <div className="toolbar">
            <label className="scenarioPicker">
              <span>Scenario</span>
              <select
                value={drillScenario}
                disabled={drillRunning}
                onChange={(event) => setDrillScenario(event.target.value as LiveIncidentDrillScenario)}
              >
                {drillScenarios.map((scenario) => (
                  <option key={scenario.value} value={scenario.value}>
                    {scenario.label}
                  </option>
                ))}
              </select>
            </label>
            <button className="primaryAction" onClick={startLiveIncidentDrill} disabled={drillRunning || loading}>
              {drillRunning ? <LoaderCircle className="spin" size={16} /> : <Play size={16} />}
              {drillRunning ? "Running live drill" : "Run live incident drill"}
            </button>
            <button onClick={() => refresh()} disabled={loading}>
              <RefreshCw size={16} />
              Refresh
            </button>
          </div>
        </header>

        {error && <div className="errorBar">{error}</div>}
        {(drillRunning || drill) && <LiveDrillProgress running={drillRunning} drill={drill} />}
        {activeIncident && (
          <IncidentOverview incident={activeIncident} loading={loading} onDecision={approveIncident} />
        )}

        <div className="canvasLayout">
          <section className="graphPane">
            <div className="paneTitle">
              <div className="viewTabs">
                <button className={view === "graph" ? "active" : ""} onClick={() => setView("graph")}>
                  <Network size={14} /> Evidence graph
                </button>
                <button
                  className={view === "timeline" ? "active" : ""}
                  onClick={() => setView("timeline")}
                >
                  <Timer size={14} /> Timeline
                </button>
              </div>
              {activeSummary && <SeverityBadge severity={activeSummary.max_severity} />}
            </div>
            {activeRun ? (
              view === "graph" ? (
                <GraphCanvas graph={activeRun} onSelectNode={setSelectedNode} />
              ) : (
                <RunTimeline graph={activeRun} onSelectNode={setSelectedNode} />
              )
            ) : (
              <div className="emptyState">
                <ShieldCheck size={34} />
                <span>Waiting for real MCP agent trace events from the Python collector.</span>
              </div>
            )}
          </section>

          <aside className="inspector">
            <section>
              <h2>Splunk Evidence</h2>
              <div className="splEvidence">
                <code>{splQuery || "Select a run to generate its verification SPL."}</code>
                <button
                  disabled={!splQuery}
                  onClick={async () => {
                    await navigator.clipboard.writeText(splQuery);
                    setCopied(true);
                    window.setTimeout(() => setCopied(false), 1500);
                  }}
                >
                  {copied ? <Check size={15} /> : <Clipboard size={15} />}
                  {copied ? "Copied" : "Copy SPL"}
                </button>
              </div>
            </section>

            <section>
              <h2>Policy Findings</h2>
              <div className="findingList">
                {activeRun?.findings.map((finding) => (
                  <article className="findingItem" key={finding.id}>
                    <SeverityBadge severity={finding.severity} />
                    <strong>{finding.title}</strong>
                    <p>{finding.summary}</p>
                    <small>{finding.recommendation}</small>
                  </article>
                ))}
                {activeRun && !activeRun.findings.length && (
                  <p className="emptyText">No policy findings for this run.</p>
                )}
              </div>
            </section>

            <section>
              <h2>Selected Node</h2>
              <NodeInspector node={selectedNode} />
            </section>
          </aside>
        </div>
      </section>
    </main>
  );
}

function LiveDrillProgress({
  running,
  drill
}: {
  running: boolean;
  drill: LiveIncidentDrillResult | null;
}) {
  return (
    <section className={`drillProgress ${drill?.status === "failed" ? "failed" : ""}`}>
      <div className="drillProgressHeading">
        <div>
          <span>Real integrations only</span>
          <strong>
            {running
              ? "Executing live incident pipeline"
              : `${drill?.scenario_label ?? "Live pipeline"} ${drill?.status}`}
          </strong>
        </div>
        {running ? <LoaderCircle className="spin" size={20} /> : drill?.status === "completed" ? <Check size={20} /> : <X size={20} />}
      </div>
      {drill && (
        <div className="drillStages">
          {drill.stages.map((stage) => (
            <div className={`drillStage ${stage.status}`} key={stage.id}>
              {stage.status === "completed" ? <Check size={15} /> : <X size={15} />}
              <span>
                <strong>{stage.label}</strong>
                <small>{stage.detail}</small>
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="metric">
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function IncidentOverview({
  incident,
  loading,
  onDecision
}: {
  incident: IncidentBrief;
  loading: boolean;
  onDecision: (decision: "approved" | "rejected") => void;
}) {
  return (
    <section className="incidentOverview">
      <div className="incidentHeading">
        <div>
          <span className="incidentEyebrow">Deployment incident / {incident.deployment_id}</span>
          <h2>{incident.title}</h2>
          <p>{incident.probable_cause}</p>
        </div>
        <SeverityBadge severity={incident.severity} />
      </div>
      <div className="incidentMetrics">
        <IncidentMetric label="Confidence" value={`${incident.confidence}%`} />
        <IncidentMetric label="Error increase" value={`${incident.error_multiplier}x`} />
        <IncidentMetric label="Services" value={incident.affected_services.length.toString()} />
        <IncidentMetric label="Regions" value={incident.affected_regions.length.toString()} />
      </div>
      <div className="incidentDetailGrid">
        <div>
          <strong>Evidence-backed action</strong>
          <p>{incident.proposed_action}</p>
          <small>Citations: {incident.evidence_node_ids.join(", ")}</small>
        </div>
        <div>
          <strong>Safe query proposal</strong>
          <code>{incident.safe_query ?? "No query rewrite required."}</code>
        </div>
        <div className="incidentActions">
          <span className={`approvalStatus approval-${incident.approval_status}`}>
            {incident.approval_status}
          </span>
          <span className="slackStatus">
            <MessageSquare size={14} /> Slack: {incident.slack_status}
          </span>
          {incident.approval_status === "pending" && (
            <>
              <button disabled={loading} onClick={() => onDecision("approved")}>
                <Check size={15} /> Approve
              </button>
              <button className="dangerButton" disabled={loading} onClick={() => onDecision("rejected")}>
                <X size={15} /> Reject
              </button>
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function IncidentMetric({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function RunTimeline({ graph, onSelectNode }: { graph: RunGraph; onSelectNode: (node: GraphNode) => void }) {
  const sorted = [...graph.nodes].sort((a, b) =>
    String(a.data.timestamp ?? "").localeCompare(String(b.data.timestamp ?? ""))
  );
  return (
    <div className="timeline">
      {sorted.map((node, index) => (
        <button className="timelineRow" key={node.id} onClick={() => onSelectNode(node)}>
          <span className={`timelineDot ${node.risk_tags.length ? "risky" : ""}`}>{index + 1}</span>
          <span className="timelineBody">
            <strong>{node.type}</strong>
            <small>{node.label}</small>
          </span>
          <time>{formatTime(node.data.timestamp)}</time>
        </button>
      ))}
    </div>
  );
}

function NodeInspector({ node }: { node: GraphNode | null }) {
  if (!node) return <p className="emptyText">Select an evidence node to inspect it.</p>;
  const payload = (node.data.payload ?? {}) as Record<string, unknown>;
  return (
    <div className="nodeInspector">
      <div className="nodeTitle">
        <span className={`trust trust-${node.trust}`}>{node.trust}</span>
        <strong>{node.type}</strong>
      </div>
      <p>{node.label}</p>
      <dl>
        <dt>Event</dt>
        <dd>{String(node.data.event_type ?? "unknown")}</dd>
        <dt>Agent</dt>
        <dd>{String(node.data.agent_id ?? "unknown")}</dd>
        <dt>Timestamp</dt>
        <dd>{String(node.data.timestamp ?? "unknown")}</dd>
      </dl>
      <pre className="nodeJson">{JSON.stringify(payload, null, 2)}</pre>
    </div>
  );
}

function formatTime(value: unknown) {
  if (!value) return "";
  const parsed = new Date(String(value));
  return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toLocaleTimeString();
}

function StatusRow({ label, ok }: { label: string; ok: boolean | null }) {
  const state = ok === null ? "unavailable" : ok ? "connected" : "not connected";
  return (
    <div className="statusRow">
      <span>{label}</span>
      <strong className={ok === null ? "unknown" : ok ? "ok" : "bad"}>{state}</strong>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`severity severity-${severity}`}>{severity}</span>;
}
