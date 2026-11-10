import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { History, Pause, Play } from "lucide-react";
import { api } from "@/lib/api";
import { useUI } from "@/lib/store";
import type { Topology } from "@/lib/types";
import { fmt, label } from "@/lib/utils";
import { IncidentTimeline } from "@/components/charts/Timeline";
import { TopologyGraph } from "@/components/topology/TopologyGraph";
import { Badge, Button, Card, CardBody, CardHeader, DataTable, EmptyState, PageHeader, Select, Skeleton, Switch } from "@/components/ui";

export function Replay() {
  const [closedOnly, setClosedOnly] = useState(true);
  const runs = useQuery({ queryKey: ["replay-runs", closedOnly], queryFn: () => api.replayRuns(closedOnly) });
  const [runId, setRunId] = useState("");
  useEffect(() => {
    if (!runId && runs.data?.length) setRunId(runs.data[0].run_id);
  }, [runs.data, runId]);
  const run = useQuery({ queryKey: ["replay", runId], queryFn: () => api.replay(runId), enabled: !!runId });
  const windows = run.data?.windows ?? [];
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(false);
  const selectNode = useUI((s) => s.selectNode);
  useEffect(() => setCursor(windows.length ? windows.length - 1 : 0), [runId, windows.length]);
  useEffect(() => {
    if (!playing) return;
    const id = setInterval(() => setCursor((c) => (c + 1 < windows.length ? c + 1 : (setPlaying(false), c))), 450);
    return () => clearInterval(id);
  }, [playing, windows.length]);

  const tNow = windows[cursor]?.t_end ?? 0;
  const topo: Topology | null = useMemo(() => {
    if (!run.data) return null;
    const det = (run.data.detections as any[]).filter((d) => Number(d.window) === windows[cursor]?.window);
    const score = Object.fromEntries(det.map((d) => [d.node, Number(d.probability)]));
    const rules: Record<string, string> = {};
    for (const m of (run.data.mitigations as any[]).filter((m) => Number(m.timestamp) <= tNow)) {
      if (m.action === "release") delete rules[m.node];
      else rules[m.node] = m.action;
    }
    return {
      name: run.data.topology.name, run_id: run.data.run_id,
      nodes: run.data.topology.nodes.map((n: any) => ({ ...n, probability: score[n.node_id] ?? 0, predicted: "", packet_rate: 0, mitigation: rules[n.node_id] ?? "" })),
      links: run.data.topology.links,
    };
  }, [run.data, cursor, tNow, windows]);

  return (
    <>
      <PageHeader title="Replay" subtitle="Scrub through any saved run window by window: what the detector saw, and what it did."
        note="Every run is recorded, so you can step back through one frame by frame — the scores, the alerts, the rules — to understand exactly why the defence made each call. The forensic counterpart to the live Overview."
        actions={<Switch checked={closedOnly} onCheckedChange={setClosedOnly} label="Closed-loop runs only" />} />
      <Card className="mb-5">
        <CardBody className="flex flex-wrap items-center gap-3">
          <Select value={runId} onChange={(e) => setRunId(e.target.value)} className="min-w-[320px] flex-1">
            {runs.data?.map((r) => (
              <option key={r.run_id} value={r.run_id}>
                {r.experiment} · {r.topology ?? "?"} · {r.detector ? label(r.detector) : "open loop"} · {r.n_mitigations} actions
              </option>
            ))}
          </Select>
          <Button size="sm" onClick={() => { if (cursor >= windows.length - 1) setCursor(0); setPlaying(!playing); }} disabled={!windows.length}>
            {playing ? <Pause /> : <Play />} {playing ? "Pause" : "Play"}
          </Button>
          <input type="range" min={0} max={Math.max(0, windows.length - 1)} value={cursor} onChange={(e) => setCursor(+e.target.value)}
                 className="w-64 accent-[rgb(var(--accent))]" aria-label="Replay position" />
          <span className="num font-mono text-xs text-muted">t = {fmt.s(tNow)}</span>
        </CardBody>
      </Card>
      {!runs.data?.length && !runs.isLoading ? (
        <Card><EmptyState icon={<History />} title="No saved runs" hint="Saved runs appear here after any simulation or experiment completes." /></Card>
      ) : run.isLoading || !topo ? <Skeleton className="h-[520px]" /> : (
        <div className="grid gap-5 xl:grid-cols-[1fr_1fr]">
          <Card>
            <CardHeader title="Network at this window" subtitle={run.data.meta?.description?.slice(0, 120)} />
            <CardBody className="p-2"><TopologyGraph data={topo} onSelect={selectNode} height={460} /></CardBody>
          </Card>
          <Card>
            <CardHeader title="Actions up to now" subtitle={`${run.data.mitigations.length} actions in this run`} />
            <div className="scroll-thin max-h-[500px] overflow-y-auto">
              <DataTable>
                <thead><tr><th>t</th><th>Node</th><th>Action</th><th>p</th></tr></thead>
                <tbody>{(run.data.mitigations as any[]).filter((m) => Number(m.timestamp) <= tNow).map((m, i) => (
                  <tr key={i}><td className="num text-xs">{fmt.s(Number(m.timestamp))}</td><td className="font-mono text-xs">{m.node}</td>
                    <td><Badge tone={m.action === "release" ? "good" : "bad"}>{m.action}</Badge></td><td className="num text-xs">{Number(m.confidence).toFixed(2)}</td></tr>))}</tbody>
              </DataTable>
            </div>
          </Card>
          <Card className="xl:col-span-2">
            <CardHeader title="Timeline" />
            <CardBody><IncidentTimeline windows={windows.slice(0, cursor + 1)} events={(run.data.events as any[]).filter((e) => e.t <= tNow)} /></CardBody>
          </Card>
        </div>
      )}
    </>
  );
}
