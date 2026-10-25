import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export const cn = (...inputs: ClassValue[]) => twMerge(clsx(inputs));

export const fmt = {
  pct: (v?: number | null, d = 1) => (v == null || Number.isNaN(v) ? "–" : `${(v * 100).toFixed(d)}%`),
  ms: (v?: number | null, d = 1) => (v == null ? "–" : `${v.toFixed(d)} ms`),
  num: (v?: number | null, d = 0) =>
    v == null || Number.isNaN(v) ? "–" : v.toLocaleString(undefined, { maximumFractionDigits: d, minimumFractionDigits: d }),
  mbps: (v?: number | null) => (v == null ? "–" : `${v.toFixed(2)} Mbit/s`),
  s: (v?: number | null, d = 1) => (v == null ? "–" : `${v.toFixed(d)} s`),
  p: (v?: number | null) => (v == null ? "–" : v.toFixed(3)),
};

export const severityOf = (p: number) => (p >= 0.95 ? "critical" : p >= 0.85 ? "high" : p >= 0.6 ? "medium" : "low");

/** Read a CSS token as an rgb() string, so charts follow the theme. */
export const token = (name: string, alpha = 1) => {
  const v = getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim();
  return alpha === 1 ? `rgb(${v.split(" ").join(",")})` : `rgba(${v.split(" ").join(",")},${alpha})`;
};

export const DETECTOR_LABEL: Record<string, string> = {
  threshold: "Threshold",
  autoencoder: "Autoencoder",
  random_forest: "Random Forest",
  lightgbm: "LightGBM",
  gru_seq: "GRU sequence",
  gat: "GATv2",
  egraphsage: "E-GraphSAGE",
  graphsage: "GraphSAGE",
  temporal_gnn: "Temporal GNN",
  graphsage_conformal: "GraphSAGE + conformal",
  temporal_gnn_conformal: "Temporal GNN + conformal",
  no_defence: "No defence",
  none: "No defence",
};

export const label = (d?: string | null) => (d ? DETECTOR_LABEL[d] ?? d : "–");
