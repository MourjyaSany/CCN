/**
 * Thin REST client for the NetShield-GNN API.
 *
 * In development Vite proxies /api to the FastAPI server on :8000; in the built
 * bundle the API is same-origin, so a relative base works in both cases.
 */

const BASE = "";

/**
 * Perform a JSON request and surface API errors as thrown Errors.
 *
 * @param {string} path Endpoint path, e.g. "/api/health".
 * @param {RequestInit} [options] Fetch options.
 * @returns {Promise<any>} Parsed JSON body.
 */
async function request(path, options) {
  const response = await fetch(`${BASE}${path}`, options);
  if (!response.ok) {
    let detail = response.statusText;
    try {
      detail = (await response.json()).detail || detail;
    } catch {
      /* response had no JSON body; keep the status text */
    }
    throw new Error(detail);
  }
  return response.json();
}

/** Liveness and capability report. */
export const getHealth = () => request("/api/health");

/** Every runnable scenario declared in config/experiments.yaml. */
export const getScenarios = () => request("/api/scenarios");

/** Live session state and progress. */
export const getSimulationStatus = () => request("/api/simulation/status");

/** Aggregate live network status for the KPI tiles. */
export const getNetworkStatus = () => request("/api/network/status");

/** Topology with live per-node classification and mitigation state. */
export const getTopology = () => request("/api/network/topology");

/** Latest completed window plus the top talkers. */
export const getTraffic = () => request("/api/traffic/current");

/** Full per-window QoS series for the current run. */
export const getMetrics = () => request("/api/metrics");

/**
 * Detections above the mitigation trigger.
 * @param {number} [limit] Maximum rows.
 */
export const getAlerts = (limit = 60) => request(`/api/alerts?limit=${limit}`);

/**
 * Raw per-node detection rows, including benign windows.
 * @param {number} [limit] Maximum rows.
 */
export const getDetections = (limit = 4000) =>
  request(`/api/detections?limit=${limit}`);

/**
 * Mitigation action log, newest first.
 * @param {number} [limit] Maximum rows.
 */
export const getMitigation = (limit = 60) =>
  request(`/api/mitigation?limit=${limit}`);

/** Stored evaluation results and generated artefacts. */
export const getResults = () => request("/api/results");

/** Available topology families with their tunable parameters. */
export const getTopologies = () => request("/api/topologies");

/** Available attack families with layer classification. */
export const getAttacks = () => request("/api/attacks");

/** Attack-builder form schema, defaults and limits. */
export const getAttackSchema = () => request("/api/attacks/schema");

/** Every generated figure with its fetch URL. */
export const getFigures = () => request("/api/figures");

/** The list of generated markdown reports. */
export const getReports = () => request("/api/reports");

/**
 * Fetch one markdown report.
 * @param {string} name Report filename, e.g. "RESULTS.md".
 */
export const getReport = (name) => request(`/api/reports/${name}`);

/** Manifests of every trained detector on disk. */
export const getModels = () => request("/api/models");

/** Persisted run history. */
export const getRuns = (limit = 100) => request(`/api/runs?limit=${limit}`);

/** Full dependency and NS-3 probe report. */
export const getEnvironment = () => request("/api/environment");

/**
 * Validate an attack-builder configuration without running it.
 *
 * @param {{scenario: string, overrides: object}} body Base scenario + overrides.
 * @returns {Promise<object>} `{valid, profile, ...}` or `{valid:false, error}`.
 */
export const previewAttack = (body) =>
  request("/api/attack/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

/**
 * Start a scenario on the server's background thread.
 *
 * @param {{scenario: string, speed?: number, mitigation?: boolean|null,
 *          detector?: string, duration_s?: number|null}} body Request body.
 */
export const startSimulation = (body) =>
  request("/api/simulation/start", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

/** Ask the running simulation to stop at the next window boundary. */
export const stopSimulation = () =>
  request("/api/simulation/stop", { method: "POST" });

/**
 * Fetch every polled resource in one round trip's worth of parallel requests.
 *
 * @returns {Promise<object>} Combined snapshot, or nulls for anything that failed.
 */
export async function pollAll() {
  const [status, topology, traffic, metrics, alerts, mitigation, detections] =
    await Promise.all([
      getNetworkStatus(),
      getTopology(),
      getTraffic(),
      getMetrics(),
      getAlerts(),
      getMitigation(),
      getDetections(),
    ]);
  return { status, topology, traffic, metrics, alerts, mitigation, detections };
}
