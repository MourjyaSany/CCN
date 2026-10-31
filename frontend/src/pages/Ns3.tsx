import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Cpu, MonitorPlay, Play } from "lucide-react";
import { api } from "@/lib/api";
import { fmt } from "@/lib/utils";
import {
  Badge, Button, Card, CardBody, CardHeader, DataTable, EmptyState, Field, PageHeader, Select,
  Skeleton,
} from "@/components/ui";

/**
 * Run scenarios in the real NS-3 engine and open them in the NS-3 animator
 * (NetAnim), a desktop window. NS-3 builds the actual network for every
 * topology; NetAnim replays the packets travelling through it.
 */
export function Ns3() {
  const qc = useQueryClient();
  const status = useQuery({ queryKey: ["ns3-status"], queryFn: api.ns3Status, refetchInterval: 20000 });
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const topologies = useQuery({ queryKey: ["topologies"], queryFn: api.topologies });
  const runs = useQuery({ queryKey: ["ns3-runs"], queryFn: api.ns3Runs, refetchInterval: 15000 });

  const [scenario, setScenario] = useState("exp2_udp_flood");
  const [topology, setTopology] = useState("tree");
  const [duration, setDuration] = useState(20);
  const [iot, setIot] = useState(8);
  const [bots, setBots] = useState(2);
  const [last, setLast] = useState<string | null>(null);

  const animate = useMutation({
    mutationFn: () =>
      api.ns3Animate({
        scenario, duration_s: duration,
        overrides: {
          "network.topology.family": topology,
          "simulation.n_iot_devices": iot,
          "simulation.n_attackers": bots,
          "attack.start_s": Math.max(2, Math.round(duration * 0.3)),
          "attack.duration_s": Math.max(4, Math.round(duration * 0.5)),
        },
      }),
    onSuccess: (r) => { setLast(r.run_id); qc.invalidateQueries({ queryKey: ["ns3-runs"] }); },
  });
  const open = useMutation({ mutationFn: (id: string) => api.netanimOpen(id) });

  const s = status.data;
  const ready = !!s?.available;
  const anim = !!s?.netanim_available;

  return (
    <>
      <PageHeader
        title="NS-3 engine & NetAnim"
        subtitle="Run a scenario in real NS-3 and watch the packets flow in the NS-3 animator."
        actions={
          <div className="flex items-center gap-2">
            <Badge tone={ready ? "good" : "bad"}><Cpu className="size-3" /> {ready ? `NS-3 ${s?.version}` : "NS-3 offline"}</Badge>
            <Badge tone={anim ? "good" : "warn"}><MonitorPlay className="size-3" /> {anim ? "NetAnim ready" : "NetAnim absent"}</Badge>
          </div>
        }
      />

      {status.isLoading ? <Skeleton className="h-24" /> : !ready ? (
        <Card><EmptyState icon={<Boxes />} title="NS-3 is not runnable here"
          hint={<>{s?.reason || "Set it up with"} <code className="font-mono">python scripts/setup_ns3.py</code>.</>} /></Card>
      ) : (
        <div className="grid gap-5 xl:grid-cols-[420px_1fr]">
          <Card>
            <CardHeader title="Run & visualise" subtitle={`NS-3 ${s?.version} · ${s?.distro} · ${s?.wsl_cores} cores`} />
            <CardBody className="space-y-4">
              <Field label="Scenario">
                <Select value={scenario} onChange={(e) => setScenario(e.target.value)}>
                  {(scenarios.data ?? []).map((x) => <option key={x.name} value={x.name}>{x.name}</option>)}
                </Select>
              </Field>
              <Field label="Topology">
                <Select value={topology} onChange={(e) => setTopology(e.target.value)}>
                  {(topologies.data ?? []).map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
                </Select>
              </Field>
              <div className="grid grid-cols-3 gap-3">
                <Field label={`Duration ${duration}s`}>
                  <input type="range" min={10} max={40} value={duration} onChange={(e) => setDuration(+e.target.value)} className="mt-2 w-full accent-[rgb(var(--accent))]" />
                </Field>
                <Field label={`IoT ${iot}`}>
                  <input type="range" min={4} max={24} value={iot} onChange={(e) => setIot(+e.target.value)} className="mt-2 w-full accent-[rgb(var(--accent))]" />
                </Field>
                <Field label={`Bots ${bots}`}>
                  <input type="range" min={1} max={8} value={bots} onChange={(e) => setBots(+e.target.value)} className="mt-2 w-full accent-[rgb(var(--accent))]" />
                </Field>
              </div>
              <p className="rounded-md bg-raised p-2.5 text-xs text-muted">
                Smaller and shorter scenarios animate best. This runs the real NS-3 model and keeps a
                NetAnim trace you can open below.
              </p>
              <Button variant="primary" className="w-full" onClick={() => animate.mutate()} disabled={animate.isPending}>
                <Play /> {animate.isPending ? "Running NS-3…" : "Run in NS-3"}
              </Button>
              {animate.error && <p className="text-xs text-bad">{String((animate.error as Error).message)}</p>}
              {animate.data && (
                <div className="rounded-md border border-border p-3 text-sm">
                  <div className="font-medium text-good">NS-3 run complete</div>
                  <div className="mt-1 grid grid-cols-2 gap-x-3 gap-y-1 text-xs text-muted">
                    <span>Topology</span><span className="text-fg">{animate.data.topology}</span>
                    <span>Nodes / links</span><span className="num text-fg">{animate.data.n_nodes} / {animate.data.n_links}</span>
                    <span>Packets</span><span className="num text-fg">{fmt.num(animate.data.packets_generated)}</span>
                    <span>Loss</span><span className="num text-fg">{fmt.pct(animate.data.loss_ratio, 1)}</span>
                  </div>
                  <Button className="mt-3 w-full" variant={anim ? "primary" : "secondary"} disabled={!anim || !animate.data.anim_available || open.isPending}
                    onClick={() => open.mutate(animate.data!.run_id)}>
                    <MonitorPlay /> Open this run in NetAnim
                  </Button>
                </div>
              )}
              {open.data?.opened && <p className="text-xs text-good">NetAnim window opened on the desktop. Press ▶ to play.</p>}
              {open.error && <p className="text-xs text-bad">{String((open.error as Error).message)}</p>}
            </CardBody>
          </Card>

          <Card className="flex flex-col">
            <CardHeader title="NS-3 runs with an animation" subtitle="Click to open any one in NetAnim" />
            {runs.data?.length ? (
              <DataTable>
                <thead><tr><th>Run</th><th>Topology</th><th>Packets</th><th>When</th><th /></tr></thead>
                <tbody>
                  {runs.data.map((r) => (
                    <tr key={r.run_id} className={last === r.run_id ? "[&_td]:bg-accent/10" : ""}>
                      <td className="font-mono text-xs">{r.experiment || r.run_id.slice(0, 24)}</td>
                      <td><Badge>{r.topology || "?"}</Badge></td>
                      <td className="num text-xs">{fmt.num(r.packets)}</td>
                      <td className="text-xs text-muted">{r.generated_at ? new Date(r.generated_at).toLocaleTimeString() : "–"}</td>
                      <td className="text-right">
                        <Button size="xs" variant="ghost" disabled={!anim || open.isPending} onClick={() => { setLast(r.run_id); open.mutate(r.run_id); }}>
                          <MonitorPlay /> NetAnim
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            ) : <EmptyState icon={<MonitorPlay />} title="No animated NS-3 runs yet" hint="Run one on the left to create a NetAnim trace." />}
          </Card>
        </div>
      )}
    </>
  );
}
