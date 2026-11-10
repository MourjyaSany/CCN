import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, Cpu, MonitorPlay, Play } from "lucide-react";
import { api } from "@/lib/api";
import { fmt } from "@/lib/utils";
import {
  Badge, Button, Card, CardBody, CardHeader, DataTable, EmptyState, Field, PageHeader, Select,
  Skeleton, Switch,
} from "@/components/ui";
import { MitigationTheatre } from "@/components/ns3/MitigationTheatre";

/** DDoS families the NS-3 model can generate (genuine, or load-approximated). */
const ATTACKS: Array<{ value: string; label: string; approx?: boolean }> = [
  { value: "udp_flood", label: "UDP flood" },
  { value: "http_flood", label: "HTTP flood" },
  { value: "syn_flood", label: "SYN flood", approx: true },
  { value: "ack_flood", label: "ACK flood", approx: true },
  { value: "icmp_flood", label: "ICMP flood", approx: true },
  { value: "slowloris", label: "Slowloris", approx: true },
  { value: "mixed", label: "Mixed botnet" },
];

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
  const [topology, setTopology] = useState("dumbbell");
  const [attack, setAttack] = useState("udp_flood");
  const [duration, setDuration] = useState(28);
  const [iot, setIot] = useState(10);
  const [bots, setBots] = useState(6);
  const [mitigate, setMitigate] = useState(true);
  const [last, setLast] = useState<string | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);

  const animate = useMutation({
    mutationFn: () =>
      api.ns3AnimateStart({
        scenario, duration_s: duration, mitigate,
        overrides: {
          "network.topology.family": topology,
          "attack.enabled": true,
          "attack.type": attack,
          "simulation.n_iot_devices": iot,
          "simulation.n_attackers": bots,
          "attack.start_s": 2,
          "attack.duration_s": Math.max(8, Math.round(duration * 0.6)),
          "mitigation.ns3_eval_s": 0.5,
          "mitigation.ns3_ratelimit_after": 1,
        },
      }),
    onSuccess: (job) => setJobId(job.job_id),
  });
  const animationJob = useQuery({
    queryKey: ["ns3-animation", jobId],
    queryFn: () => api.ns3AnimateJob(jobId!),
    enabled: !!jobId,
    refetchInterval: (query) =>
      query.state.data?.status === "queued" || query.state.data?.status === "running" ? 350 : false,
  });
  const runResult = animationJob.data?.result ?? null;
  const running = animate.isPending || animationJob.data?.status === "queued" ||
    animationJob.data?.status === "running";
  useEffect(() => {
    if (runResult) {
      setLast(runResult.run_id);
      qc.invalidateQueries({ queryKey: ["ns3-runs"] });
    }
  }, [runResult, qc]);
  const open = useMutation({ mutationFn: (id: string) => api.netanimOpen(id) });

  const s = status.data;
  const ready = !!s?.available;
  const anim = !!s?.netanim_available;

  return (
    <>
      <PageHeader
        title="NS-3 engine & NetAnim"
        subtitle="Run a scenario in real NS-3 and watch the packets flow in the NS-3 animator."
        note="This is the ground truth of the whole project: ns-3 builds the actual network for the chosen topology and moves real packets through it, so congestion and loss are emergent, not scripted. Run one here, then open it in NetAnim to watch every packet traverse the graph — or feed the same flows to the detector."
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
              <div className="grid grid-cols-2 gap-3">
                <Field label="Topology">
                  <Select value={topology} onChange={(e) => setTopology(e.target.value)}>
                    {(topologies.data ?? []).map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
                  </Select>
                </Field>
                <Field label="Attack type" hint={ATTACKS.find((a) => a.value === attack)?.approx ? "load-approximated in NS-3" : "volumetric, genuine"}>
                  <Select value={attack} onChange={(e) => setAttack(e.target.value)}>
                    {ATTACKS.map((a) => <option key={a.value} value={a.value}>{a.label}</option>)}
                  </Select>
                </Field>
              </div>
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
              <div className="flex items-center justify-between rounded-md border border-border bg-raised p-2.5">
                <div>
                  <div className="text-sm font-medium text-fg">Mitigate the flood</div>
                  <div className="text-[11px] text-muted">Gateway rate limiting begins at 2.5s; sustained floods escalate to a full block.</div>
                </div>
                <Switch checked={mitigate} onCheckedChange={setMitigate} />
              </div>
              <p className="rounded-md bg-raised p-2.5 text-xs text-muted">
                Runs the real NS-3 model and keeps a NetAnim trace. With mitigation on, the gateway
                starts rate-limiting at 2.5&nbsp;s, shortly after the attack begins at 2&nbsp;s.
                Sustained floods escalate to a full block: attacker nodes turn{" "}
                <span className="font-medium text-warn">orange</span> then{" "}
                <span className="font-medium text-fg">black</span>, and their packets stop reaching the
                cloud. <span className="font-medium text-fg">In NetAnim, drag the speed slider toward
                &ldquo;slow&rdquo;</span> and press ▶ so the panel can watch the cutoff happen.
              </p>
              <Button variant="primary" className="w-full" onClick={() => { setJobId(null); animate.mutate(); }} disabled={running}>
                <Play /> {running ? "Running NS-3…" : mitigate ? "Run + mitigate in NS-3" : "Run in NS-3"}
              </Button>
              {animate.error && <p className="text-xs text-bad">{String((animate.error as Error).message)}</p>}
              {animationJob.data?.error && <p className="text-xs text-bad">{animationJob.data.error}</p>}
              {animationJob.data?.progress && (
                <div className="rounded-md border border-accent/40 bg-accent/5 p-3" aria-live="polite">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-sm font-semibold text-fg">
                      Gateway blocked: {fmt.num(animationJob.data.progress.gateway_blocked_packets)} packets
                    </span>
                    <span className="num text-xs text-muted">
                      {fmt.num(animationJob.data.progress.gateway_blocked_pps)} pkt/s
                    </span>
                  </div>
                  <div className="mt-1 grid grid-cols-2 gap-2 text-xs">
                    <span className="text-bad">Malicious / attacker: {fmt.num(animationJob.data.progress.gateway_blocked_attack_packets)}</span>
                    <span className="text-good">Legitimate / non-attacker: {fmt.num(animationJob.data.progress.gateway_blocked_legit_packets)}</span>
                  </div>
                  {running && (
                    <div className="mt-1 text-[11px] text-muted">
                      Simulation {animationJob.data.progress.sim_time_s.toFixed(1)} / {animationJob.data.progress.duration_s.toFixed(1)} s
                    </div>
                  )}
                  {animationJob.data.status === "completed" && (
                    <div className="mt-1 text-[11px] text-good">Final gateway drop count</div>
                  )}
                </div>
              )}
              {runResult && (
                <div className="rounded-md border border-border p-3 text-sm">
                  {runResult.mitigated && runResult.attack_blocked_pct != null ? (
                    <>
                      {(() => {
                        const blocked = runResult.attack_blocked_pct ?? 0;
                        const legit = runResult.clean_delivered_ratio ?? 0;
                        const okB = blocked >= 0.92, okL = legit >= 0.95;
                        const Stat = ({ v, ok, label, target }: { v: number; ok: boolean; label: string; target: string }) => (
                          <div className={`flex-1 rounded-md p-3 text-center ${ok ? "bg-good/10" : "bg-bad/10"}`}>
                            <div className={`num text-2xl font-bold ${ok ? "text-good" : "text-bad"}`}>{fmt.pct(v, 1)}</div>
                            <div className={`text-[11px] font-medium ${ok ? "text-good" : "text-bad"}`}>{label}</div>
                            <div className="mt-0.5 text-[10px] text-muted">{ok ? "✓" : "✗"} target {target}</div>
                          </div>
                        );
                        return (
                          <div className="flex gap-2">
                            <Stat v={blocked} ok={okB} label="of the attack blocked" target="≥ 92%" />
                            <Stat v={legit} ok={okL} label="legit traffic delivered" target="≥ 95%" />
                          </div>
                        );
                      })()}
                      <div className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-xs text-muted">
                        <span>Topology / attack</span><span className="text-fg">{runResult.topology} · {attack}</span>
                        <span>Attack sent → reached</span>
                        <span className="num text-fg">{fmt.num(runResult.attack_offered_total ?? 0)} → {fmt.num(runResult.attack_reached_cloud ?? 0)}</span>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="font-medium text-warn">Open-loop flood — no mitigation</div>
                      <div className="mt-1 grid grid-cols-2 gap-x-3 gap-y-1 text-xs text-muted">
                        <span>Topology / attack</span><span className="text-fg">{runResult.topology} · {attack}</span>
                        <span>Attack reached cloud</span>
                        <span className="num text-bad">{fmt.num(runResult.attack_reached_cloud ?? 0)} pkts</span>
                        <span>Packets offered</span><span className="num text-fg">{fmt.num(runResult.packets_generated)}</span>
                      </div>
                    </>
                  )}
                  <Button className="mt-3 w-full" variant={anim ? "primary" : "secondary"} disabled={!anim || !runResult.anim_available || open.isPending}
                    onClick={() => open.mutate(runResult.run_id)}>
                    <MonitorPlay /> Open this run in NetAnim
                  </Button>
                  {runResult.mitigated && (
                    <div className="mt-2 rounded-md border border-border bg-raised p-2 text-[11px] text-muted">
                      <div className="mb-1 font-medium text-fg">What to watch in NetAnim</div>
                      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full" style={{ background: "rgb(150,150,150)" }} /> gateway idle</span>
                        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full" style={{ background: "rgb(255,150,0)" }} /> gateway <b>THROTTLING n&nbsp;pkt/s</b></span>
                        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full" style={{ background: "rgb(220,40,40)" }} /> gateway <b>BLOCKING n&nbsp;pkt/s</b></span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
                        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full" style={{ background: "rgb(230,50,50)" }} /> bot attacking</span>
                        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full" style={{ background: "rgb(255,150,0)" }} /> bot rate-limited</span>
                        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full bg-black ring-1 ring-border" /> bot blocked → slides to quarantine</span>
                        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full" style={{ background: "rgb(40,190,90)" }} /> IoT</span>
                        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full" style={{ background: "rgb(0,120,255)" }} /> cloud</span>
                      </div>
                      <div className="mt-1 text-subtle">The gateway label shows the cumulative blocked packets and current drop rate.</div>
                    </div>
                  )}
                </div>
              )}
              {open.data?.opened && <p className="text-xs text-good">NetAnim window opened on the desktop. Press ▶ to play.</p>}
              {open.error && <p className="text-xs text-bad">{String((open.error as Error).message)}</p>}
            </CardBody>
          </Card>

          <div className="space-y-5">
          <Card>
            <CardHeader title="What the gateway does to the flood"
              subtitle="Red = attack packets, green = legit. Watch red packets get stopped (✕) or slowed at the gateway while legit traffic keeps flowing." />
            <CardBody>
              <MitigationTheatre
                blockedPct={runResult?.mitigated ? runResult.attack_blocked_pct : undefined}
                topology={runResult?.topology}
                attackType={attack}
              />
            </CardBody>
          </Card>

          <Card className="flex flex-col">
            <CardHeader title="NS-3 runs with an animation" subtitle="Click to open any one in NetAnim" />
            {runs.data?.length ? (
              <DataTable>
                <thead><tr><th>Run</th><th>Topology</th><th>Mitigation</th><th>When</th><th /></tr></thead>
                <tbody>
                  {runs.data.map((r) => (
                    <tr key={r.run_id} className={last === r.run_id ? "[&_td]:bg-accent/10" : ""}>
                      <td className="font-mono text-xs">{r.experiment || r.run_id.slice(0, 24)}</td>
                      <td><Badge>{r.topology || "?"}</Badge></td>
                      <td className="text-xs">
                        {r.mitigated
                          ? <Badge tone="good">{r.attack_blocked_pct != null ? `${fmt.pct(r.attack_blocked_pct, 0)} blocked` : "mitigated"}</Badge>
                          : <Badge tone="warn">open-loop</Badge>}
                      </td>
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
        </div>
      )}
    </>
  );
}
