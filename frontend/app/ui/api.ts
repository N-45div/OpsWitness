import type { IncidentBrief, LiveIncidentDrillResult, RunGraph, RunSummary, SplunkStatus } from "./types";

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

export function runLiveIncidentDrill() {
  return request<LiveIncidentDrillResult>("/drills/live-incident", {
    method: "POST",
    body: JSON.stringify({})
  });
}

export function apiBase() {
  return API_BASE;
}
