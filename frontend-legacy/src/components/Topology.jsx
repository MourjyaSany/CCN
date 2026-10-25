/**
 * Live topology view.
 *
 * Rendered as inline SVG with a deterministic tier layout rather than a
 * force-directed graph library: the network *is* hierarchical (cloud → gateway →
 * routers → devices), so a tier layout communicates the structure that matters
 * — where traffic aggregates — while a force layout would scramble it and jitter
 * on every poll.
 *
 * Nodes are coloured by predicted class and ringed when they are ground-truth
 * compromised, so a viewer can see at a glance where the model is right.
 */

import React, { useMemo } from "react";

const WIDTH = 1000;
const HEIGHT = 430;
const PAD = 56;

const TIER_NAMES = ["Cloud", "Edge gateway", "Access routers", "IoT devices"];

/** Radius by node role — infrastructure is drawn larger. */
function radiusOf(kind) {
  if (kind === "cloud") return 17;
  if (kind === "gateway") return 14;
  if (kind === "router") return 11;
  return 7;
}

/** Fill colour: mitigation state wins, then predicted class, then role. */
function colourOf(node) {
  if (node.mitigation) return "var(--violet)";
  if (node.predicted === "MALICIOUS") return "var(--critical)";
  if (node.predicted === "SUSPICIOUS") return "var(--warning)";
  if (node.kind === "iot" || node.kind === "attacker") return "var(--good)";
  return "var(--series-1)";
}

export default function Topology({ topology }) {
  const layout = useMemo(() => {
    if (!topology?.nodes?.length) return null;

    const tiers = new Map();
    for (const node of topology.nodes) {
      if (!tiers.has(node.tier)) tiers.set(node.tier, []);
      tiers.get(node.tier).push(node);
    }
    const tierKeys = [...tiers.keys()].sort((a, b) => a - b);
    const positions = new Map();

    tierKeys.forEach((tier, index) => {
      const row = [...tiers.get(tier)].sort((a, b) =>
        a.node_id.localeCompare(b.node_id),
      );
      const y = PAD + (index / Math.max(1, tierKeys.length - 1)) * (HEIGHT - 2 * PAD);
      row.forEach((node, i) => {
        positions.set(node.node_id, {
          x: PAD + ((i + 1) / (row.length + 1)) * (WIDTH - 2 * PAD),
          y,
          node,
        });
      });
    });

    return { positions, tierKeys };
  }, [topology]);

  if (!layout) {
    return (
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="topology">
        <text
          x={WIDTH / 2}
          y={HEIGHT / 2}
          textAnchor="middle"
          fill="var(--text-muted)"
          fontSize="15"
        >
          Start a simulation to render the live topology
        </text>
      </svg>
    );
  }

  const { positions, tierKeys } = layout;

  return (
    <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="topology">
      {/* Link width encodes bandwidth on a log scale. */}
      {(topology.links || []).map((link, i) => {
        const a = positions.get(link.source);
        const b = positions.get(link.target);
        if (!a || !b) return null;
        const width =
          0.6 + Math.log10(Math.max(1, (link.bandwidth_bps || 1e6) / 1e6)) * 0.9;
        return (
          <line
            key={`link-${i}`}
            x1={a.x}
            y1={a.y}
            x2={b.x}
            y2={b.y}
            stroke="var(--border-strong)"
            strokeWidth={width}
          />
        );
      })}

      {[...positions.values()].map(({ x, y, node }) => {
        const r = radiusOf(node.kind);
        return (
          <g key={node.node_id}>
            {node.is_attacker && (
              <circle
                cx={x}
                cy={y}
                r={r + 4}
                fill="none"
                stroke="var(--critical)"
                strokeWidth="1.6"
                strokeDasharray="2.5 2.5"
                opacity="0.8"
              />
            )}
            <circle
              cx={x}
              cy={y}
              r={r}
              fill={colourOf(node)}
              stroke="var(--surface-1)"
              strokeWidth="2"
            >
              <title>
                {`${node.node_id} (${node.kind}) ${node.ip}\n` +
                  `class: ${node.predicted}  P(hostile)=${(node.probability || 0).toFixed(3)}\n` +
                  `rate: ${(node.packet_rate || 0).toFixed(1)} pkt/s` +
                  (node.mitigation ? `\naction: ${node.mitigation}` : "") +
                  (node.is_attacker ? "\nground truth: COMPROMISED" : "")}
              </title>
            </circle>
            {node.kind !== "iot" && node.kind !== "attacker" && (
              <text
                x={x}
                y={y - r - 7}
                textAnchor="middle"
                fontSize="11"
                fill="var(--text-secondary)"
              >
                {node.node_id}
              </text>
            )}
          </g>
        );
      })}

      {tierKeys.map((tier, index) => {
        const y = PAD + (index / Math.max(1, tierKeys.length - 1)) * (HEIGHT - 2 * PAD);
        return (
          <text
            key={`tier-${tier}`}
            x={8}
            y={y + 4}
            fontSize="11"
            fontWeight="600"
            fill="var(--text-muted)"
          >
            {TIER_NAMES[tier] || `Tier ${tier}`}
          </text>
        );
      })}
    </svg>
  );
}
