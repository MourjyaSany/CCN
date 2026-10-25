import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Brain, ShieldOff } from "lucide-react";
import { api } from "@/lib/api";
import { can, useAuth, useUI } from "@/lib/store";
import type { TopoNode } from "@/lib/types";
import { fmt } from "@/lib/utils";
import { Chart, SERIES, type EOption } from "@/components/charts/Chart";
import { Badge, Button, DataTable, Drawer, EmptyState, SeverityBadge, Skeleton } from "@/components/ui";

const GROUP_LABEL: Record<string, string> = {
  egress_volume: "Egress volume", packet_size: "Packet sizes", timing: "Timing",
  addressing: "Addressing / fan-out", protocol_mix: "Protocol mix", tcp_flags: "TCP flags",
  ingress: "Ingress", structural: "Structure",
};

function AttributionBars({ rows }: { rows: Array<{ name: string; value: number }> }) {
  const max = Math.max(1e-9, ...rows.map((r) => Math.abs(r.value)));
  return (
    <div className="space-y-1.5">
      {rows.map((r) => (
        <div key={r.name} className="grid grid-cols-[150px_1fr_64px] items-center gap-2 text-xs">
          <span className="truncate text-muted" title={r.name}>{r.name}</span>
          <div className="relative h-3 rounded bg-border/40">
            <div className="absolute inset-y-0 left-1/2 w-px bg-subtle/60" />
            <div
              className={r.value >= 0 ? "absolute inset-y-0 left-1/2 rounded-r bg-bad/80" : "absolute inset-y-0 right-1/2 rounded-l bg-good/80"}
              style={{ width: `${(Math.abs(r.value) / max) * 50}%` }}
            />
          </div>
          <span className="num text-right font-mono">{r.value >= 0 ? "+" : ""}{r.value.toFixed(3)}</span>
        </div>
      ))}
    </div>
  );
}

export function NodeDrawer({ node }: { node: TopoNode | undefined }) {
  const { selectedNode, selectNode } = useUI();
  const role = useAuth((s) => s.role);
  const qc = useQueryClient();
  const open = !!selectedNode;
  const history = useQuery({ queryKey: ["history", selectedNode], queryFn: () => api.nodeHistory(selectedNode!), enabled: open, refetchInterval: 3000 });
  const explain = useQuery({ queryKey: ["explain", selectedNode], queryFn: () => api.explain(selectedNode!), enabled: open, retry: false });
  const rollback = useMutation({ mutationFn: () => api.rollback(selectedNode!), onSuccess: () => qc.invalidateQueries() });

  const h = history.data?.history ?? [];
  const option: EOption = {
    grid: { left: 40, right: 44, top: 20, bottom: 24 },
    legend: { top: 0, right: 0, itemWidth: 10, itemHeight: 6 },
    xAxis: { type: "value", name: "t (s)", nameLocation: "end" },
    yAxis: [{ type: "value", min: 0, max: 1, name: "P(hostile)" }, { type: "value", name: "pps", splitLine: { show: false } }],
    series: [
      { name: "P(hostile)", type: "line", data: h.map((r) => [r.timestamp, r.probability]), symbol: "none", lineStyle: { width: 2, color: SERIES[5] },
        markLine: { silent: true, symbol: "none", lineStyle: { type: "dashed", color: SERIES[6] }, data: [{ yAxis: 0.8, label: { formatter: "trigger" } }] } },
      { name: "egress pps", type: "line", yAxisIndex: 1, data: h.map((r) => [r.timestamp, r.packet_rate]), symbol: "none", lineStyle: { width: 1.2, color: SERIES[0] } },
    ],
  };
  const e = explain.data;

  return (
    <Drawer
      open={open}
      onOpenChange={(o) => !o && selectNode(null)}
      title={<span className="font-mono">{selectedNode}</span>}
      subtitle={node ? `${node.kind} · ${node.ip} ${node.device_class ? `· ${node.device_class}` : ""}` : undefined}
    >
      {node && (
        <div className="mb-4 grid grid-cols-3 gap-3">
          <div><div className="label">P(hostile)</div><div className="num mt-1 text-lg font-semibold">{node.probability.toFixed(3)}</div></div>
          <div><div className="label">Class</div><div className="mt-1"><SeverityBadge p={node.probability} /></div></div>
          <div><div className="label">Rule</div><div className="mt-1">{node.mitigation ? <Badge tone="bad">{node.mitigation}</Badge> : <Badge>none</Badge>}</div></div>
        </div>
      )}
      <section className="mb-5">
        <h4 className="label mb-2">Score history</h4>
        {history.isLoading ? <Skeleton className="h-40" /> : h.length ? <Chart option={option} height={180} /> : <EmptyState title="No scores yet for this node" />}
      </section>

      <section className="mb-5">
        <h4 className="label mb-2 flex items-center gap-1.5"><Brain className="size-3.5" /> Why this score</h4>
        {explain.isLoading && <Skeleton className="h-40" />}
        {explain.isError && <p className="text-xs text-muted">No explanation available: the node may be silent in the latest window, or no detector is running.</p>}
        {e && (
          <div className="space-y-4">
            <p className="text-xs text-muted">
              {e.method === "integrated_gradients"
                ? <>Integrated gradients on <b>{e.detector}</b>, window {e.window}. Score {e.score.toFixed(3)} vs. baseline {e.baseline_score?.toFixed(3)}; {fmt.pct(Math.abs(e.self_attribution ?? 0) / Math.max(1e-9, Math.abs(e.self_attribution ?? 0) + Math.abs(e.neighbour_attribution ?? 0)), 0)} of the evidence comes from the node itself, the rest from its neighbourhood.</>
                : <>Feature-group occlusion on <b>{e.detector}</b>, window {e.window}: how much the score drops when each group is replaced by a typical peer's values.</>}
            </p>
            <div>
              <div className="mb-1.5 text-xs font-medium">Feature groups</div>
              <AttributionBars rows={e.feature_groups.map((g) => ({ name: GROUP_LABEL[g.group] ?? g.group, value: g.delta }))} />
            </div>
            {e.features.length > 0 && (
              <div>
                <div className="mb-1.5 text-xs font-medium">Top features</div>
                <AttributionBars rows={e.features.map((f) => ({ name: f.feature, value: f.attribution }))} />
              </div>
            )}
            {e.neighbours.length > 0 && (
              <div>
                <div className="mb-1.5 text-xs font-medium">Neighbour influence</div>
                <AttributionBars rows={e.neighbours.map((n) => ({ name: n.node, value: n.attribution }))} />
              </div>
            )}
          </div>
        )}
      </section>

      <section>
        <h4 className="label mb-2">Mitigation actions</h4>
        {history.data?.actions.length ? (
          <DataTable>
            <thead><tr><th>t</th><th>Action</th><th>p</th><th>Reason</th></tr></thead>
            <tbody>
              {history.data.actions.map((a, i) => (
                <tr key={i}><td className="num">{fmt.s(a.timestamp)}</td><td><Badge tone={a.action === "release" ? "good" : "bad"}>{a.action}</Badge></td>
                  <td className="num">{a.confidence.toFixed(2)}</td><td className="text-xs text-muted">{a.reason}</td></tr>
              ))}
            </tbody>
          </DataTable>
        ) : <p className="text-xs text-muted">No rule has been applied to this node.</p>}
        {node?.mitigation && can(role, "operator") && (
          <Button variant="danger" size="sm" className="mt-3" onClick={() => rollback.mutate()} disabled={rollback.isPending}>
            <ShieldOff /> Roll back rule
          </Button>
        )}
      </section>
    </Drawer>
  );
}
