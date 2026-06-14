export type Severity = "none" | "low" | "medium" | "high" | "critical";

export type RunSummary = {
  run_id: string;
  nodes: number;
  edges: number;
  findings: number;
  max_severity: Severity;
  started_at?: string | null;
  updated_at?: string | null;
  agent_id: string;
  tool_calls: number;
};

export type GraphNode = {
  id: string;
  type: string;
  label: string;
  trust: "trusted" | "untrusted" | "unknown";
  risk_tags: string[];
  data: Record<string, unknown>;
};

export type GraphEdge = {
  source: string;
  target: string;
  type: string;
  label: string;
  risk_tags: string[];
  data: Record<string, unknown>;
};

export type Finding = {
  id: string;
  run_id: string;
  severity: Exclude<Severity, "none">;
  title: string;
  summary: string;
  risk_tags: string[];
  path: string[];
  evidence: Record<string, unknown>;
  recommendation: string;
};

export type RunGraph = {
  run_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  findings: Finding[];
};

export type SplunkStatus = {
  hec: {
    configured: boolean;
    reachable: boolean;
    status_code?: number | null;
    detail: string;
    ack_mode: "auto" | "required" | "disabled";
  };
  search: {
    configured: boolean;
    reachable: boolean;
    status_code?: number | null;
    detail: string;
  };
  mcp_proxy: {
    configured: boolean;
    upstream_url: boolean;
    preflight_configured: boolean;
    native_anomaly_requires_tool: string;
  };
  slack: {
    configured: boolean;
  };
  hosted_model: {
    configured: boolean;
    model_name?: string | null;
    mode?: "mltk_model" | "unavailable";
  };
  foundation_sec: {
    configured: boolean;
    model_name: string;
    provider: string;
    splunk_hosted: false;
  };
  cdtsm: {
    configured: boolean;
    ready: boolean;
    detail: string;
  };
  soar: {
    configured: boolean;
    reachable: boolean;
    status_code?: number | null;
    detail: string;
  };
  mcp_required_capability: string;
};

export type IncidentBrief = {
  incident_id: string;
  run_id: string;
  deployment_id: string;
  title: string;
  severity: Exclude<Severity, "none">;
  probable_cause: string;
  confidence: number;
  baseline_errors: number;
  current_errors: number;
  error_multiplier: number;
  affected_services: string[];
  affected_regions: string[];
  evidence_node_ids: string[];
  unsafe_query?: string | null;
  safe_query?: string | null;
  proposed_action: string;
  approval_status: "pending" | "approved" | "rejected";
  slack_status: "not_configured" | "sent" | "failed" | "not_requested";
  slack_detail?: string | null;
  soar_status: "not_configured" | "executed" | "failed" | "not_requested";
  soar_detail?: string | null;
  created_at: string;
  updated_at: string;
};

export type LiveIncidentDrillStage = {
  id: string;
  label: string;
  status: "completed" | "failed" | "unavailable";
  detail: string;
};

export type LiveIncidentDrillResult = {
  status: "completed" | "failed";
  scenario: LiveIncidentDrillScenario;
  scenario_label: string;
  run_id: string;
  deployment_id: string;
  incident_id?: string | null;
  stages: LiveIncidentDrillStage[];
  incident?: IncidentBrief | null;
};

export type LiveIncidentDrillScenario =
  | "deployment_regression"
  | "credential_attack"
  | "queue_saturation";

export type LiveIncidentDrillJob = {
  job_id: string;
  status: "queued" | "running" | "completed" | "failed";
  result?: LiveIncidentDrillResult | null;
};
