import { useEffect, useRef } from "react";
import cytoscape, { type Core } from "cytoscape";
import type { Topology } from "@/lib/types";
import { useUI } from "@/lib/store";
import { token } from "@/lib/utils";

/**
 * Deterministic tiered layout: cloud on top, then gateways, routers, and the
 * devices grouped under their parent. Parents are centred over their children,
 * so the tree reads top-down and stays put between refreshes.
 */
function tieredPositions(data: Topology): Record<string, { x: number; y: number }> {
  const tier = (n: Topology["nodes"][number]) =>
    n.kind === "cloud" ? 0 : n.kind === "gateway" ? 1 : n.kind === "router" ? 2 : 3;
  const leaves = data.nodes.filter((n) => tier(n) === 3)
    .sort((a, b) => (a.parent ?? "").localeCompare(b.parent ?? "") || a.node_id.localeCompare(b.node_id));
  const pos: Record<string, { x: number; y: number }> = {};
  const gap = 46;
  leaves.forEach((n, i) => (pos[n.node_id] = { x: i * gap, y: 3 * 150 }));
  const width = Math.max(1, leaves.length - 1) * gap;
  for (const t of [2, 1, 0]) {
    const level = data.nodes.filter((n) => tier(n) === t).sort((a, b) => a.node_id.localeCompare(b.node_id));
    level.forEach((n, i) => {
      const kids = data.nodes.filter((k) => k.parent === n.node_id && pos[k.node_id]);
      const x = kids.length ? kids.reduce((s, k) => s + pos[k.node_id].x, 0) / kids.length
                            : ((i + 1) / (level.length + 1)) * width;
      pos[n.node_id] = { x, y: t * 150 };
    });
  }
  return pos;
}

/**
 * Interactive topology. Nodes are coloured by P(hostile), outlined when a
 * mitigation rule is installed, sized by role; edge width tracks capacity.
 * Positions are kept between refreshes so the graph does not jump.
 */
export function TopologyGraph({ data, onSelect, height = 560 }: {
  data: Topology; onSelect: (id: string) => void; height?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core>();
  const dark = useUI((s) => s.dark);
  const selected = useUI((s) => s.selectedNode);

  useEffect(() => {
    if (!ref.current) return;
    cy.current = cytoscape({ container: ref.current, wheelSensitivity: 0.25, minZoom: 0.2, maxZoom: 3 });
    cy.current.on("tap", "node", (e) => onSelect(e.target.id()));
    return () => cy.current?.destroy();
  }, [onSelect]);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    const good = token("good"), warn = token("warn"), bad = token("bad"), accent = token("accent");
    const nodeColour = (p: number, kind: string) =>
      kind === "cloud" ? accent : kind === "gateway" || kind === "router" ? token("subtle") : p >= 0.85 ? bad : p >= 0.6 ? warn : good;
    const ids = new Set<string>();
    c.batch(() => {
      for (const n of data.nodes) {
        ids.add(n.node_id);
        const d = {
          id: n.node_id,
          label: n.kind === "iot" || n.kind === "attacker" ? n.node_id.replace(/^(iot|atk)-/, "") : n.node_id,
          kind: n.kind,
          colour: nodeColour(n.probability, n.kind),
          size: n.kind === "cloud" ? 46 : n.kind === "gateway" ? 38 : n.kind === "router" ? 30 : 22,
          ruled: n.mitigation ? 1 : 0,
          shape: n.kind === "cloud" ? "round-rectangle" : n.kind === "gateway" ? "diamond" : n.kind === "router" ? "hexagon" : "ellipse",
        };
        const el = c.getElementById(n.node_id);
        if (el.nonempty()) el.data(d);
        else c.add({ group: "nodes", data: d });
      }
      for (const l of data.links) {
        const id = `${l.source}__${l.target}`;
        ids.add(id);
        if (c.getElementById(id).empty() && c.getElementById(`${l.target}__${l.source}`).empty()) {
          c.add({ group: "edges", data: { id, source: l.source, target: l.target, w: Math.max(1, Math.log10(l.bandwidth_bps || 1e6) - 5) } });
        } else ids.add(`${l.target}__${l.source}`);
      }
      c.elements().filter((e) => !ids.has(e.id())).remove();
    });
    c.style([
      { selector: "node", style: {
        "background-color": "data(colour)", width: "data(size)", height: "data(size)", shape: "data(shape)" as any,
        label: "data(label)", "font-size": 9, color: token("muted"), "text-valign": "bottom", "text-margin-y": 3,
        "border-width": (e: any) => (e.data("ruled") ? 4 : 0), "border-color": token("fg"),
      } },
      { selector: "node:selected", style: { "border-width": 4, "border-color": accent, "overlay-opacity": 0 } },
      { selector: "edge", style: { width: "data(w)", "line-color": token("border"), "curve-style": "bezier", opacity: 0.9 } },
    ]);
    if (c.scratch("_laidOut") !== data.run_id && data.nodes.length) {
      c.layout({ name: "preset", positions: tieredPositions(data), fit: true, padding: 24, animate: false } as any).run();
      c.scratch("_laidOut", data.run_id);
    }
  }, [data, dark]);

  useEffect(() => {
    const c = cy.current;
    if (!c) return;
    c.$("node:selected").unselect();
    if (selected) c.getElementById(selected).select();
  }, [selected]);

  return <div ref={ref} style={{ height }} className="w-full rounded-md bg-raised" aria-label="Network topology graph" role="img" />;
}
