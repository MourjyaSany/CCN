import { useCallback, useMemo, useState } from "react";
import { Network } from "lucide-react";
import { api } from "@/lib/api";
import { useLiveQuery } from "@/lib/live";
import { useUI } from "@/lib/store";
import { fmt } from "@/lib/utils";
import { TopologyGraph } from "@/components/topology/TopologyGraph";
import { NodeDrawer } from "@/components/topology/NodeDrawer";
import { Badge, Card, CardBody, CardHeader, DataTable, EmptyState, Input, PageHeader, SeverityBadge, Skeleton } from "@/components/ui";

export function LiveNetwork() {
  const topo = useLiveQuery("topology", api.topology, 2000);
  const selectNode = useUI((s) => s.selectNode);
  const selected = useUI((s) => s.selectedNode);
  const [q, setQ] = useState("");
  const onSelect = useCallback((id: string) => selectNode(id), [selectNode]);
  const nodes = topo.data?.nodes ?? [];
  const endpoints = useMemo(
    () => nodes.filter((n) => n.kind === "iot" || n.kind === "attacker")
      .filter((n) => !q || n.node_id.includes(q) || n.ip.includes(q))
      .sort((a, b) => b.probability - a.probability),
    [nodes, q],
  );
  const ruled = nodes.filter((n) => n.mitigation).length;
  const hot = nodes.filter((n) => n.probability >= 0.8).length;
  return (
    <>
      <PageHeader title="Live network" subtitle="Click any node for its score history, the reason it was flagged, and the rules applied to it."
        note="The graph the GNN actually reasons over. Each node is a simulated device coloured by its current P(hostile); edges are real links. This is where you see the detector's view of the network update window by window as the attack unfolds." />
      <div className="grid gap-5 xl:grid-cols-[1fr_420px]">
        <Card>
          <CardHeader title={topo.data?.name || "Topology"} subtitle={`${nodes.length} nodes · ${hot} above trigger · ${ruled} under a rule`}
            actions={
              <div className="hidden items-center gap-3 text-[11px] text-muted md:flex">
                <span className="flex items-center gap-1"><span className="size-2.5 rounded-full bg-good" />benign</span>
                <span className="flex items-center gap-1"><span className="size-2.5 rounded-full bg-warn" />p ≥ 0.6</span>
                <span className="flex items-center gap-1"><span className="size-2.5 rounded-full bg-bad" />p ≥ 0.85</span>
                <span className="flex items-center gap-1"><span className="size-2.5 rounded-full border-2 border-fg" />rule</span>
              </div>
            } />
          <CardBody className="p-2">
            {topo.isLoading ? <Skeleton className="h-[560px]" /> : nodes.length ? (
              <TopologyGraph data={topo.data!} onSelect={onSelect} />
            ) : <EmptyState icon={<Network />} title="No topology yet" hint="Start a scenario from the Overview page." />}
          </CardBody>
        </Card>
        <Card className="flex flex-col">
          <CardHeader title="Endpoints by risk" actions={<Input placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-36" />} />
          <div className="scroll-thin max-h-[600px] overflow-y-auto">
            <DataTable>
              <thead><tr><th>Node</th><th>p</th><th>pps</th><th>Rule</th></tr></thead>
              <tbody>
                {endpoints.map((n) => (
                  <tr key={n.node_id} onClick={() => selectNode(n.node_id)} className={`cursor-pointer ${selected === n.node_id ? "[&_td]:bg-accent/10" : ""}`}>
                    <td><div className="font-mono text-xs">{n.node_id}</div><div className="text-[11px] text-subtle">{n.ip}</div></td>
                    <td><div className="flex items-center gap-2"><span className="num font-mono text-xs">{n.probability.toFixed(2)}</span><SeverityBadge p={n.probability} /></div></td>
                    <td className="num text-xs">{fmt.num(n.packet_rate, 1)}</td>
                    <td>{n.mitigation ? <Badge tone="bad">{n.mitigation}</Badge> : <span className="text-xs text-subtle">–</span>}</td>
                  </tr>
                ))}
              </tbody>
            </DataTable>
          </div>
        </Card>
      </div>
      <NodeDrawer node={nodes.find((n) => n.node_id === selected)} />
    </>
  );
}
