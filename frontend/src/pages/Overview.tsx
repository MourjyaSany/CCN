import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Play, ShieldAlert, Square, Timer } from "lucide-react";
import { api } from "@/lib/api";
import { useLiveQuery } from "@/lib/live";
import { can, useAuth, useUI } from "@/lib/store";
import { fmt, label } from "@/lib/utils";
import { Sparkline, SERIES } from "@/components/charts/Chart";
import { IncidentTimeline } from "@/components/charts/Timeline";
import {
  Badge, Button, Card, CardBody, CardHeader, EmptyState, Field, PageHeader, Select, SeverityBadge,
  Skeleton, Switch,
} from "@/components/ui";

function Kpi({ title, value, sub, series, colour, tone }: {
  title: string; value: string; sub?: string; series?: number[]; colour?: string; tone?: "good" | "warn" | "bad";
}) {
  return (
    <Card className="p-4">
      <div className="label">{title}</div>
      <div className={`num mt-1.5 text-2xl font-semibold ${tone === "bad" ? "text-bad" : tone === "warn" ? "text-warn" : "text-fg"}`}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-muted">{sub}</div>}
      {series && series.length > 1 && <div className="mt-2"><Sparkline data={series} color={colour} /></div>}
    </Card>
  );
}

export function Launcher() {
  const qc = useQueryClient();
  const role = useAuth((s) => s.role);
  const live = useUI((s) => s.live);
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const [scenario, setScenario] = useState("exp8_mitigation");
  const [detector, setDetector] = useState("");
  const loaded = health.data?.detectors_loaded ?? [];
  const preferred = ["temporal_gnn", "graphsage", "lightgbm", "random_forest"].find((d) => loaded.includes(d)) ?? loaded[0];
  const [mitigation, setMitigation] = useState(true);
  const [mode, setMode] = useState("auto");
  const [speed, setSpeed] = useState(5);
  const start = useMutation({
    mutationFn: () => api.start({ scenario, detector: detector || preferred, speed, mitigation,
                                  overrides: { "mitigation.approval_mode": mode } }),
    onSuccess: () => qc.invalidateQueries(),
  });
  const stop = useMutation({ mutationFn: api.stop, onSuccess: () => qc.invalidateQueries() });
  const running = live?.state === "running";
  const allowed = can(role, "operator");
  return (
    <Card>
      <CardHeader title="Run a scenario" subtitle="Launch a simulation with the detector in the loop." />
      <CardBody className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
        <div className="sm:col-span-2">
          <Field label="Scenario">
            <Select value={scenario} onChange={(e) => setScenario(e.target.value)}>
              {scenarios.data?.map((s) => <option key={s.name} value={s.name}>{s.name}</option>)}
            </Select>
          </Field>
        </div>
        <Field label="Detector">
          <Select value={detector || preferred || ""} onChange={(e) => setDetector(e.target.value)}>
            {(health.data?.detectors_loaded ?? []).map((d) => <option key={d} value={d}>{label(d)}</option>)}
          </Select>
        </Field>
        <Field label="Approval mode" hint="hybrid: blocks wait for you">
          <Select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="auto">automatic</option><option value="hybrid">hybrid</option><option value="manual">manual</option>
          </Select>
        </Field>
        <Field label={`Speed ${speed}x`}>
          <input type="range" min={1} max={30} value={speed} onChange={(e) => setSpeed(+e.target.value)} className="mt-2 accent-[rgb(var(--accent))]" />
        </Field>
        <div className="flex items-end gap-3">
          <Switch checked={mitigation} onCheckedChange={setMitigation} label="Mitigate" />
          {running ? (
            <Button variant="danger" onClick={() => stop.mutate()} disabled={!allowed}><Square /> Stop</Button>
          ) : (
            <Button variant="primary" onClick={() => start.mutate()} disabled={!allowed || start.isPending || !health.data?.detectors_loaded.length}><Play /> Start</Button>
          )}
        </div>
        {start.error && <p className="text-xs text-bad sm:col-span-full">{String(start.error.message)}</p>}
        {health.data && !health.data.detectors_loaded.length && (
          <p className="text-xs text-warn sm:col-span-full">No trained detector found. Run setup first; the one-click launcher does this for you.</p>
        )}
      </CardBody>
    </Card>
  );
}

export function Overview() {
  const live = useUI((s) => s.live);
  const timeline = useLiveQuery("timeline", api.timeline);
  const alerts = useLiveQuery("alerts", () => api.alerts(50));
  const w = timeline.data?.windows ?? [];
  const last = w[w.length - 1];
  const base = w.slice(0, 5);
  const baseAvail = base.length ? base.reduce((a, b) => a + (b.clean_availability ?? 1), 0) / base.length : undefined;
  const events = timeline.data?.events ?? [];
  const tStart = events.find((e) => e.kind === "attack_start")?.t;
  const tDet = events.find((e) => e.kind === "first_detection")?.t;
  const tMit = events.find((e) => e.kind === "first_mitigation")?.t;
  const avail = last?.clean_availability;
  return (
    <>
      <PageHeader title="Overview" subtitle="Service health of the uninfected fleet, and what the defence is doing about it."
        note="Mission control for a live run. Start a scenario below, then watch whether the healthy devices keep their service while the GNN hunts the botnet and the gateway enforces rules. Every figure here is measured from the simulated packets — detection latency, goodput, recovery — never assumed." />
      <div className="mb-5"><Launcher /></div>
      {timeline.isLoading ? (
        <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-6">{Array.from({ length: 6 }).map((_, i) => <Skeleton key={i} className="h-28" />)}</div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-6">
          <Kpi title="Clean availability" value={fmt.pct(avail)} sub={baseAvail ? `baseline ${fmt.pct(baseAvail)}` : "packets on time / offered"}
               series={w.map((x) => x.clean_availability ?? 0)} colour={SERIES[2]} tone={avail != null && avail < 0.95 ? "bad" : undefined} />
          <Kpi title="p99 latency" value={fmt.ms(last?.clean_p99_latency_ms)} sub={`p50 ${fmt.ms(last?.clean_p50_latency_ms)}`} series={w.map((x) => x.clean_p99_latency_ms ?? 0)} colour={SERIES[1]} />
          <Kpi title="Goodput" value={fmt.mbps(last?.throughput_mbps)} sub={`offered ${fmt.mbps(last?.offered_mbps)}`} series={w.map((x) => x.throughput_mbps ?? 0)} colour={SERIES[0]} />
          <Kpi title="Nodes flagged" value={fmt.num(last?.flagged_nodes)} sub="this window" series={w.map((x) => x.flagged_nodes ?? 0)} colour={SERIES[6]} tone={(last?.flagged_nodes ?? 0) > 0 ? "warn" : undefined} />
          <Kpi title="Rules active" value={fmt.num(last?.mitigated_sources)} sub={`collateral ${fmt.pct(last?.collateral_byte_ratio, 2)}`} series={w.map((x) => x.mitigated_sources ?? 0)} colour={SERIES[3]} />
          <Kpi title="Time to detect / mitigate" value={tStart != null && tDet != null ? fmt.s(tDet - tStart) : "–"}
               sub={tStart != null && tMit != null ? `mitigated after ${fmt.s(tMit - tStart)}` : "since attack start"} />
        </div>
      )}
      <div className="mt-5 grid gap-5 xl:grid-cols-[1fr_380px]">
        <Card>
          <CardHeader title="Incident timeline" subtitle={live?.scenario ? `${live.scenario} · ${live.state}` : "No run yet"}
            actions={<Button asChild variant="ghost" size="sm"><Link to="/incidents">Open <ArrowRight /></Link></Button>} />
          <CardBody>
            {w.length ? <IncidentTimeline windows={w} events={events} compact /> :
              <EmptyState icon={<Timer />} title="Nothing to plot yet" hint="Start a scenario above. Charts fill window by window as the simulation advances." />}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Top threats" subtitle="Highest-confidence alerts in this run"
            actions={<Button asChild variant="ghost" size="sm"><Link to="/alerts">All <ArrowRight /></Link></Button>} />
          <div className="divide-y divide-border">
            {(alerts.data ?? []).slice().sort((a, b) => b.confidence - a.confidence).slice(0, 8).map((a, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                <ShieldAlert className="size-4 text-bad" />
                <div className="min-w-0 flex-1">
                  <div className="font-mono text-xs">{a.node_id}</div>
                  <div className="truncate text-xs text-muted">{a.message}</div>
                </div>
                <SeverityBadge p={a.confidence} />
                <Badge className="num">{a.confidence.toFixed(2)}</Badge>
              </div>
            ))}
            {!alerts.data?.length && <EmptyState title="No alerts" hint="Alerts appear when a node crosses the trigger probability." />}
          </div>
        </Card>
      </div>
    </>
  );
}
