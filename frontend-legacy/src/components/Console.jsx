/**
 * Live console: KPI tiles, topology, time series and the alert/mitigation logs
 * for the simulation currently running on the server.
 *
 * This is the view that shows mitigation closing the loop: the KPI tiles and
 * the topology update every window, so a rule installed at t = 40 s is visibly
 * followed by uplink utilisation and clean loss falling while the attack is
 * still running.
 */

import React from "react";

import Charts from "./Charts.jsx";
import Topology from "./Topology.jsx";

/** Format a number for display, or an em dash when it is absent. */
export const fmt = (value, digits = 1) =>
  value === null || value === undefined || Number.isNaN(value)
    ? "—"
    : Number(value).toLocaleString(undefined, {
        minimumFractionDigits: digits,
        maximumFractionDigits: digits,
      });

function Kpi({ label, value, unit, foot, tone }) {
  return (
    <div className={`kpi ${tone || ""}`}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">
        {value}
        {unit && <span className="kpi-unit">{unit}</span>}
      </div>
      <div className="kpi-foot">{foot || " "}</div>
    </div>
  );
}

export default function Console({
  snapshot,
  scenarios,
  health,
  scenario,
  setScenario,
  detector,
  setDetector,
  speed,
  setSpeed,
  mitigation,
  setMitigation,
  onStart,
  onStop,
  running,
  error,
}) {
  const status = snapshot.status || {};
  const lossPct = (status.clean_packet_loss || 0) * 100;

  return (
    <>
      <section className="controls">
        <div className="field">
          <label htmlFor="scenario">Scenario</label>
          <select
            id="scenario"
            value={scenario}
            onChange={(e) => setScenario(e.target.value)}
          >
            {scenarios.map((s) => (
              <option key={s.name} value={s.name}>
                {s.name} — {s.attack_type || "benign"}
                {s.n_attackers ? `, ${s.n_attackers} bots` : ""}
              </option>
            ))}
          </select>
        </div>

        <div className="field">
          <label htmlFor="detector">Detector</label>
          <select
            id="detector"
            value={detector}
            onChange={(e) => setDetector(e.target.value)}
            disabled={!health?.detectors_loaded?.length}
          >
            {(health?.detectors_loaded?.length
              ? health.detectors_loaded
              : ["(none trained)"]
            ).map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </div>

        <div className="field">
          <label htmlFor="speed">Speed (sim s / real s)</label>
          <input
            id="speed"
            type="number"
            min="0"
            max="60"
            value={speed}
            onChange={(e) => setSpeed(e.target.value)}
          />
        </div>

        <label className="check">
          <input
            type="checkbox"
            checked={mitigation}
            onChange={(e) => setMitigation(e.target.checked)}
          />
          Automated mitigation
        </label>

        <button className="primary" onClick={onStart} disabled={running}>
          ▶ Start simulation
        </button>
        <button className="danger" onClick={onStop} disabled={!running}>
          ■ Stop
        </button>

        <div className="spacer" />
        <div className="progress-wrap">
          <div className="progress-label">
            {status.duration_s
              ? `t = ${fmt(status.sim_time_s)} s of ${fmt(status.duration_s, 0)} s`
              : "not running"}
          </div>
          <div className="progress">
            <i style={{ width: `${(status.progress || 0) * 100}%` }} />
          </div>
        </div>
      </section>

      {error && <div className="error">{error}</div>}

      <div className="kpis">
        <Kpi label="Devices" value={status.n_devices ?? 0}
             foot={`${status.n_routers ?? 0} routers + gateway + cloud`} />
        <Kpi label="Packet rate" value={fmt(status.packets_per_second, 0)}
             unit="pkt/s" foot="offered, last window" />
        <Kpi label="Throughput" value={fmt(status.throughput_mbps, 2)}
             unit="Mbit/s" foot="delivered at cloud" />
        <Kpi label="Latency"
             value={fmt(status.clean_latency_ms || status.latency_ms)}
             unit="ms" foot="uncompromised devices"
             tone={(status.clean_latency_ms || 0) > 80 ? "warn" : "ok"} />
        <Kpi label="Clean loss" value={fmt(lossPct, 2)} unit="%"
             foot="uncompromised devices"
             tone={lossPct > 5 ? "alert" : lossPct > 1 ? "warn" : "ok"} />
        <Kpi label="Uplink use"
             value={fmt((status.uplink_utilisation || 0) * 100)} unit="%"
             foot="gateway → cloud"
             tone={(status.uplink_utilisation || 0) > 0.9 ? "alert" : ""} />
        <Kpi label="Suspicious" value={status.n_suspicious ?? 0}
             foot="nodes this window"
             tone={status.n_suspicious ? "warn" : ""} />
        <Kpi label="Malicious" value={status.n_malicious ?? 0}
             foot="nodes this window"
             tone={status.n_malicious ? "alert" : ""} />
        <Kpi label="Mitigated" value={status.n_mitigated ?? 0}
             foot="rules installed"
             tone={status.n_mitigated ? "ok" : ""} />
        <Kpi label="Max confidence" value={fmt(status.max_confidence, 3)}
             foot={`${status.detector || "detector"} P(hostile)`}
             tone={(status.max_confidence || 0) >= 0.8 ? "alert" : ""} />
      </div>

      <section className="panel">
        <h2>
          Network topology{" "}
          <span className="hint">
            {snapshot.topology?.n_nodes
              ? `${snapshot.topology.family || "tree"} · ${snapshot.topology.n_nodes} nodes · ${snapshot.topology.n_links} links`
              : "IoT → routers → edge gateway → cloud"}
          </span>
        </h2>
        <Topology topology={snapshot.topology} />
        <div className="legend">
          <span><i className="swatch" style={{ background: "var(--good)" }} />Benign</span>
          <span><i className="swatch" style={{ background: "var(--warning)" }} />Suspicious</span>
          <span><i className="swatch" style={{ background: "var(--critical)" }} />Malicious</span>
          <span><i className="swatch" style={{ background: "var(--violet)" }} />Mitigated</span>
          <span><i className="swatch" style={{ background: "var(--series-1)" }} />Infrastructure</span>
          <span className="muted">Ring = ground-truth compromised node</span>
        </div>
      </section>

      <Charts metrics={snapshot.metrics} detections={snapshot.detections} />

      <div className="two-col">
        <section className="panel">
          <h2>
            Alerts <span className="hint">above the mitigation trigger</span>
          </h2>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th className="num">t (s)</th><th>Node</th><th>Severity</th>
                  <th className="num">Conf.</th><th className="num">pkt/s</th>
                </tr>
              </thead>
              <tbody>
                {(snapshot.alerts || []).length === 0 ? (
                  <tr><td colSpan={5} className="empty">No alerts.</td></tr>
                ) : (
                  snapshot.alerts.map((a, i) => (
                    <tr key={i}>
                      <td className="num">{fmt(a.timestamp)}</td>
                      <td className="mono">{a.node_id}</td>
                      <td><span className={`tag ${a.severity}`}>{a.severity}</span></td>
                      <td className="num">{fmt(a.confidence, 3)}</td>
                      <td className="num">{fmt(a.packet_rate, 0)}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="panel">
          <h2>
            Mitigation actions <span className="hint">installed at the gateway</span>
          </h2>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th className="num">t (s)</th><th>Node</th><th>Action</th>
                  <th className="num">Conf.</th><th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {(snapshot.mitigation || []).length === 0 ? (
                  <tr><td colSpan={5} className="empty">No mitigation actions yet.</td></tr>
                ) : (
                  snapshot.mitigation.map((m, i) => (
                    <tr key={i}>
                      <td className="num">{fmt(m.timestamp)}</td>
                      <td className="mono">{m.node}</td>
                      <td><span className={`tag ${m.action}`}>{m.action}</span></td>
                      <td className="num">{fmt(m.confidence, 3)}</td>
                      <td className="reason">{m.reason}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </>
  );
}
