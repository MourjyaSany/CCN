/**
 * Time-series panels.
 *
 * Deliberately **no dual-axis charts**: quantities with different units get
 * their own panel sharing an x-axis, so a reader can line up "the attack
 * starts", "the detector fires" and "loss recovers" without decoding two
 * y-scales. The attack interval is shaded and the first mitigation action is
 * marked, so each panel is readable without a caption.
 */

import React from "react";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ReferenceArea,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const SERIES_1 = "#2a78d6";
const SERIES_2 = "#eb6834";
const SERIES_3 = "#1baf7a";
const SERIES_8 = "#e34948";
const ATTACK_SHADE = "#e34948";
const MITIGATION = "#1baf7a";

const AXIS = { fontSize: 11, stroke: "var(--text-muted)" };

/** Shared chart chrome: grid, axes, attack band, mitigation marker. */
function Frame({ data, children, yLabel, attack, mitigation, domain }) {
  return (
    <ResponsiveContainer width="100%" height={210}>
      <LineChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: -8 }}>
        <CartesianGrid stroke="var(--border)" vertical={false} />
        {attack?.enabled && (
          <ReferenceArea
            x1={attack.start_s}
            x2={attack.end_s}
            fill={ATTACK_SHADE}
            fillOpacity={0.08}
          />
        )}
        {mitigation != null && (
          <ReferenceLine
            x={mitigation}
            stroke={MITIGATION}
            strokeDasharray="4 3"
            strokeWidth={1.6}
          />
        )}
        <XAxis
          dataKey="t"
          type="number"
          domain={["dataMin", "dataMax"]}
          tick={AXIS}
          tickFormatter={(v) => `${Math.round(v)}s`}
        />
        <YAxis tick={AXIS} domain={domain || [0, "auto"]} width={52}
               label={{ value: yLabel, angle: -90, position: "insideLeft",
                        style: { fontSize: 10, fill: "var(--text-muted)" } }} />
        <Tooltip
          contentStyle={{
            background: "var(--surface-2)",
            border: "1px solid var(--border-strong)",
            borderRadius: 8,
            fontSize: 12,
          }}
          labelFormatter={(v) => `t = ${Number(v).toFixed(1)} s`}
        />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        {children}
      </LineChart>
    </ResponsiveContainer>
  );
}

export default function Charts({ metrics, detections }) {
  const windows = metrics?.windows || [];
  const attack = metrics?.attack || {};
  const mitigation = metrics?.first_mitigation_s ?? null;

  // Maximum detector confidence per window, taken from the full detection log
  // rather than the alert list, so benign windows are shown too.
  const confidence = new Map();
  for (const row of detections || []) {
    const w = Number(row.window);
    confidence.set(w, Math.max(confidence.get(w) || 0, Number(row.probability) || 0));
  }

  const data = windows.map((w) => ({
    t: Number(w.t_end),
    throughput: Number(w.throughput_mbps),
    offered: Number(w.offered_mbps),
    latency: Number(w.clean_mean_latency_ms ?? w.mean_latency_ms),
    loss: Number(w.clean_loss_ratio ?? w.legit_loss_ratio) * 100,
    confidence: confidence.get(Number(w.window)) || 0,
  }));

  if (!data.length) {
    return <div className="empty">No data yet — start a simulation.</div>;
  }

  return (
    <div className="chart-grid">
      <section className="panel">
        <h2>
          Throughput vs offered load <span className="hint">Mbit/s</span>
        </h2>
        <Frame data={data} yLabel="Mbit/s" attack={attack} mitigation={mitigation}>
          <Line type="monotone" dataKey="throughput" name="Delivered at cloud"
                stroke={SERIES_1} strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="offered" name="Offered"
                stroke={SERIES_2} strokeWidth={2} strokeDasharray="5 3" dot={false} />
        </Frame>
      </section>

      <section className="panel">
        <h2>
          Latency <span className="hint">uncompromised devices, ms</span>
        </h2>
        <Frame data={data} yLabel="ms" attack={attack} mitigation={mitigation}>
          <Line type="monotone" dataKey="latency" name="Mean end-to-end delay"
                stroke={SERIES_1} strokeWidth={2} dot={false} />
        </Frame>
      </section>

      <section className="panel">
        <h2>
          Packet loss <span className="hint">uncompromised devices, %</span>
        </h2>
        <Frame data={data} yLabel="%" attack={attack} mitigation={mitigation}>
          <Line type="monotone" dataKey="loss" name="Loss"
                stroke={SERIES_8} strokeWidth={2} dot={false} />
        </Frame>
      </section>

      <section className="panel">
        <h2>
          Detector confidence <span className="hint">max P(hostile) per window</span>
        </h2>
        <Frame data={data} yLabel="P(hostile)" attack={attack}
               mitigation={mitigation} domain={[0, 1]}>
          <ReferenceLine y={0.8} stroke="var(--text-muted)" strokeDasharray="4 3" />
          <Line type="monotone" dataKey="confidence" name="Max confidence"
                stroke={SERIES_3} strokeWidth={2} dot={false} />
        </Frame>
      </section>
    </div>
  );
}
