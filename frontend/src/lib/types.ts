export type SimState = "idle" | "running" | "stopping" | "completed" | "failed";

export interface Health {
  status: string;
  version: string;
  engine: string;
  ns3_available: boolean;
  gnn_backend: string;
  detectors_loaded: string[];
  dataset_available: boolean;
}

export interface Scenario {
  name: string;
  description: string;
  tags: string[];
  n_iot_devices: number;
  n_attackers: number;
  duration_s: number;
  attack_type: string;
  attack_start_s: number | null;
  attack_duration_s: number | null;
  mitigation_enabled: boolean;
}

export interface WindowPoint {
  window: number;
  t_start: number;
  t_end: number;
  clean_availability?: number;
  clean_p50_latency_ms?: number;
  clean_p99_latency_ms?: number;
  clean_jitter_ms?: number;
  clean_loss_ratio?: number;
  throughput_mbps?: number;
  offered_mbps?: number;
  uplink_utilisation?: number;
  attack_offered?: number;
  legit_offered?: number;
  mitigation_drops?: number;
  collateral_byte_ratio?: number;
  clean_fairness?: number;
  mitigated_sources?: number;
  flagged_nodes?: number;
}

export interface IncidentEvent {
  t: number;
  kind: "attack_start" | "attack_end" | "first_detection" | "first_mitigation" | "recovered";
  label: string;
}

export interface MitigationAction {
  timestamp: number;
  window: number;
  node: string;
  ip?: string;
  action: string;
  confidence: number;
  reason?: string;
  detector?: string;
}

export interface Timeline {
  state: SimState;
  scenario: string;
  run_id: string;
  sim_time_s: number;
  duration_s: number;
  windows: WindowPoint[];
  mitigations: MitigationAction[];
  events: IncidentEvent[];
}

export interface TopoNode {
  node_id: string;
  kind: string;
  ip: string;
  device_class: string;
  tier: number;
  parent: string | null;
  is_attacker: boolean;
  probability: number;
  predicted: string;
  packet_rate: number;
  mitigation: string;
}

export interface TopoLink {
  source: string;
  target: string;
  bandwidth_bps: number;
  delay_ms: number;
}

export interface Topology {
  name: string;
  run_id: string;
  nodes: TopoNode[];
  links: TopoLink[];
}

export interface Alert {
  timestamp: number;
  window: number;
  node_id: string;
  ip: string;
  severity: string;
  confidence: number;
  detector: string;
  packet_rate: number;
  message: string;
}

export interface Approval {
  id: number;
  node: string;
  action: string;
  confidence: number;
  window: number;
  timestamp: number;
  reason: string;
  status: "pending" | "approved" | "rejected";
  decided_by: string | null;
}

export interface LiveSnapshot {
  state: SimState;
  scenario: string;
  run_id: string;
  sim_time_s: number;
  duration_s: number;
  progress: number;
  detector: string;
  mitigation_enabled: boolean;
  latest_window: Partial<WindowPoint>;
  recent_detections: Array<{ node: string; probability: number; window: number; timestamp: number; is_attacker: boolean }>;
  pending_approvals: Approval[];
}

export interface Explanation {
  method: "integrated_gradients" | "occlusion";
  node: string;
  window: number;
  detector: string;
  score: number;
  baseline_score?: number;
  completeness_gap?: number;
  self_attribution?: number;
  neighbour_attribution?: number;
  features: Array<{ feature: string; attribution: number; value: number | null }>;
  neighbours: Array<{ node: string; kind: string; attribution: number }>;
  feature_groups: Array<{ group: string; delta: number }>;
}

export interface ReplayRun {
  run_id: string;
  experiment: string;
  topology: string;
  detector: string | null;
  n_windows: number;
  n_detections: number;
  n_mitigations: number;
  generated_at: string;
}
