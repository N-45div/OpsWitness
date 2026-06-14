import type {
  IncidentBrief,
  LiveIncidentDrillJob,
  LiveIncidentDrillResult,
  LiveIncidentDrillScenario,
  RunGraph,
  RunSummary,
  SplunkStatus
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE ?? "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    cache: "no-store",
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {})
    }
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`${response.status} ${response.statusText}: ${body}`);
  }
  return response.json() as Promise<T>;
}

export function listRuns() {
  return request<RunSummary[]>("/runs");
}

export function getRun(runId: string) {
  return request<RunGraph>(`/runs/${runId}`);
}

export function splunkStatus() {
  return request<SplunkStatus>("/splunk/status");
}

export function getRunSpl(runId: string) {
  return request<{ query: string }>(`/runs/${runId}/spl`);
}

export function listIncidents() {
  return request<IncidentBrief[]>("/incidents");
}

export function decideIncident(
  incidentId: string,
  decision: "approved" | "rejected",
  approver = "incident-commander"
) {
  return request<IncidentBrief>(`/incidents/${incidentId}/approval`, {
    method: "POST",
    body: JSON.stringify({ decision, approver })
  });
}

export function runLiveIncidentDrill(scenario: LiveIncidentDrillScenario) {
  return startLiveIncidentDrill(scenario).then(pollLiveIncidentDrill);
}

function startLiveIncidentDrill(scenario: LiveIncidentDrillScenario) {
  return request<LiveIncidentDrillJob>("/drills/live-incident/jobs", {
    method: "POST",
    body: JSON.stringify({ scenario })
  });
}

async function pollLiveIncidentDrill(job: LiveIncidentDrillJob): Promise<LiveIncidentDrillResult> {
  const deadline = Date.now() + 180_000;
  let current = job;
  while (Date.now() < deadline) {
    if (current.result) return current.result;
    await new Promise((resolve) => window.setTimeout(resolve, 1500));
    current = await request<LiveIncidentDrillJob>(`/drills/live-incident/jobs/${job.job_id}`);
  }
  throw new Error("Live drill exceeded the three-minute execution window");
}

export function apiBase() {
  return API_BASE;
}
