import { useAuth } from "./store";
import type {
  Alert, Approval, Explanation, Health, LiveSnapshot, MitigationAction, ReplayRun, Scenario,
  Timeline, Topology,
} from "./types";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = useAuth.getState().token;
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof URLSearchParams) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(path, { ...init, headers });
  if (res.status === 401) useAuth.getState().expire();
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail ?? detail;
    } catch {
      /* no JSON body */
    }
    throw new ApiError(res.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  const type = res.headers.get("content-type") ?? "";
  return (type.includes("json") ? res.json() : res.text()) as Promise<T>;
}

const post = <T,>(path: string, body?: unknown) =>
  request<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

export const api = {
  health: () => request<Health>("/api/health"),
  me: () => request<{ username: string; role: string; auth_enabled: boolean }>("/api/auth/me"),
  login: (username: string, password: string) =>
    request<{ access_token: string; role: string; expires_in: number }>("/api/auth/token", {
      method: "POST",
      body: new URLSearchParams({ username, password }),
    }),
  scenarios: () => request<Scenario[]>("/api/scenarios"),
  status: () => request<LiveSnapshot>("/api/simulation/status"),
  start: (body: { scenario: string; detector?: string; speed?: number; mitigation?: boolean; overrides?: Record<string, unknown> }) =>
    post("/api/simulation/start", body),
  stop: () => post("/api/simulation/stop"),
  timeline: () => request<Timeline>("/api/timeline"),
  topology: () => request<Topology>("/api/network/topology"),
  alerts: (limit = 300) => request<Alert[]>(`/api/alerts?limit=${limit}`),
  mitigation: (limit = 300) => request<MitigationAction[]>(`/api/mitigation?limit=${limit}`),
  approvals: (status = "all") => request<Approval[]>(`/api/approvals?status=${status}`),
  approve: (id: number) => post(`/api/approvals/${id}/approve`),
  reject: (id: number) => post(`/api/approvals/${id}/reject`),
  rollback: (node: string) => post(`/api/mitigation/${encodeURIComponent(node)}/rollback`),
  policy: () => request<Record<string, unknown> & { approval_mode: string }>("/api/policy"),
  setPolicy: (approval_mode: string) => post("/api/policy", { approval_mode }),
  nodeHistory: (node: string) =>
    request<{ node: string; history: Array<{ window: number; timestamp: number; probability: number; packet_rate: number; predicted: string }>; actions: MitigationAction[] }>(
      `/api/nodes/${encodeURIComponent(node)}/history`,
    ),
  explain: (node: string) => request<Explanation>(`/api/explain/${encodeURIComponent(node)}`),
  replayRuns: (closedLoopOnly = false) => request<ReplayRun[]>(`/api/replay/runs?limit=120&closed_loop_only=${closedLoopOnly}`),
  replay: (runId: string) => request<any>(`/api/replay/${encodeURIComponent(runId)}`),
  research: () => request<{ tables: Record<string, any[]>; figures: string[]; report_available: boolean }>("/api/research/summary"),
  exportAlerts: (fmt: "stix" | "cef") => request<string | object>(`/api/alerts/export?fmt=${fmt}&min_probability=0.8`),
  audit: () => request<{ chain_valid: boolean; entries: any[] }>("/api/audit?limit=300"),
  attacks: () => request<any[]>("/api/attacks"),
  topologies: () => request<any[]>("/api/topologies"),
  // --- NS-3 engine + NetAnim ---
  ns3Status: () => request<{ available: boolean; version?: string; distro?: string; netanim_available?: boolean; wsl_cores?: string; wsl_kernel?: string; reason?: string }>("/api/ns3/status"),
  ns3Animate: (body: { scenario: string; duration_s?: number; overrides?: Record<string, unknown> }) =>
    post<{ run_id: string; engine: string; topology: string; n_nodes: number; n_links: number; packets_generated: number; loss_ratio: number; anim_available: boolean; approximations: string[] }>("/api/ns3/animate", body),
  netanimOpen: (run_id: string) => post<{ opened: boolean; run_id: string; pid: number | null }>("/api/ns3/netanim/open", { run_id }),
  ns3Runs: () => request<Array<{ run_id: string; experiment: string; topology: string; engine: string; packets: number; generated_at: string }>>("/api/ns3/runs"),
};
