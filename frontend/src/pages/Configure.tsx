import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FlaskConical, Lock, Play, Swords } from "lucide-react";
import { api } from "@/lib/api";
import { can, useAuth, useUI } from "@/lib/store";
import { fmt, label } from "@/lib/utils";
import {
  Badge, Button, Card, CardBody, CardHeader, DataTable, EmptyState, Field, Input, PageHeader, Segmented,
  Select, Switch,
} from "@/components/ui";

/* --------------------------------------------------------------- Experiments */
export function Experiments() {
  const scenarios = useQuery({ queryKey: ["scenarios"], queryFn: api.scenarios });
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const role = useAuth((s) => s.role);
  const nav = useNavigate();
  const qc = useQueryClient();
  const [tag, setTag] = useState("all");
  const start = useMutation({
    mutationFn: (scenario: string) => api.start({ scenario, detector: health.data?.detectors_loaded.includes("graphsage") ? "graphsage" : health.data?.detectors_loaded[0], speed: 8, mitigation: true }),
    onSuccess: () => { qc.invalidateQueries(); nav("/incidents"); },
  });
  const tags = [...new Set((scenarios.data ?? []).flatMap((s) => s.tags))].sort();
  const rows = (scenarios.data ?? []).filter((s) => tag === "all" || s.tags.includes(tag));
  return (
    <>
      <PageHeader title="Experiments" subtitle="Every scenario in config/experiments.yaml. Launching one runs it with GraphSAGE in the loop and opens the timeline."
        actions={<Select value={tag} onChange={(e) => setTag(e.target.value)}><option value="all">All tags</option>{tags.map((t) => <option key={t}>{t}</option>)}</Select>} />
      <Card>
        <DataTable>
          <thead><tr><th>Scenario</th><th>Description</th><th>Attack</th><th>Fleet</th><th>Duration</th><th /></tr></thead>
          <tbody>{rows.map((s) => (
            <tr key={s.name}>
              <td><div className="font-mono text-xs font-medium">{s.name}</div><div className="mt-1 flex flex-wrap gap-1">{s.tags.map((t) => <Badge key={t}>{t}</Badge>)}</div></td>
              <td className="max-w-md text-xs text-muted">{s.description}</td>
              <td>{s.attack_type ? <Badge tone="bad">{s.attack_type}</Badge> : <Badge tone="good">none</Badge>}</td>
              <td className="num text-xs">{s.n_iot_devices} + {s.n_attackers} bots</td>
              <td className="num text-xs">{fmt.s(s.duration_s, 0)}</td>
              <td><Button size="xs" variant="primary" disabled={!can(role, "operator") || start.isPending} onClick={() => start.mutate(s.name)}><Play /> Run</Button></td>
            </tr>))}</tbody>
        </DataTable>
        {!rows.length && <EmptyState icon={<FlaskConical />} title="No scenarios" />}
      </Card>
    </>
  );
}

/* ------------------------------------------------------------ Attack builder */
export function AttackBuilder() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const attacks = useQuery({ queryKey: ["attacks"], queryFn: api.attacks });
  const topologies = useQuery({ queryKey: ["topologies"], queryFn: api.topologies });
  const role = useAuth((s) => s.role);
  const nav = useNavigate();
  const qc = useQueryClient();
  const [f, setF] = useState({ type: "udp_flood", pps: 1400, bots: 4, start: 30, duration: 40, topology: "tree", burst: false,
                               on: 2, off: 3, profile: "constant", jitter: 0.2, stagger: 0, detector: "graphsage", mode: "auto" });
  const set = (k: keyof typeof f, v: any) => setF({ ...f, [k]: v });
  const launch = useMutation({
    mutationFn: () => api.start({
      scenario: "exp2_udp_flood", detector: f.detector, speed: 8, mitigation: true, duration_s: f.start + f.duration + 20,
      overrides: {
        "attack.type": f.type, "attack.packets_per_second": f.pps, "simulation.n_attackers": f.bots,
        "attack.start_s": f.start, "attack.duration_s": f.duration, "network.topology.family": f.topology,
        "attack.burst.enabled": f.burst, "attack.burst.on_s": f.on, "attack.burst.off_s": f.off,
        "attack.shape.profile": f.profile, "attack.rate_jitter": [1 - f.jitter, 1 + f.jitter], "attack.stagger_s": f.stagger,
        "mitigation.approval_mode": f.mode,
      },
    } as any),
    onSuccess: () => { qc.invalidateQueries(); nav("/network"); },
  });
  return (
    <>
      <PageHeader title="Attack builder" subtitle="Compose a campaign the corpus never contained, then watch the defence respond." />
      <div className="grid gap-5 xl:grid-cols-[1fr_360px]">
        <Card>
          <CardHeader title="Campaign" />
          <CardBody className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
            <Field label="Attack family"><Select value={f.type} onChange={(e) => set("type", e.target.value)}>{(attacks.data ?? []).map((a) => <option key={a.name} value={a.name}>{a.name}</option>)}</Select></Field>
            <Field label="Topology"><Select value={f.topology} onChange={(e) => set("topology", e.target.value)}>{(topologies.data ?? []).map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}</Select></Field>
            <Field label="Bots"><Input type="number" min={1} max={30} value={f.bots} onChange={(e) => set("bots", +e.target.value)} /></Field>
            <Field label="Rate per bot (pps)" hint="HTTP floods: transactions per second"><Input type="number" min={1} value={f.pps} onChange={(e) => set("pps", +e.target.value)} /></Field>
            <Field label="Start (s)"><Input type="number" value={f.start} onChange={(e) => set("start", +e.target.value)} /></Field>
            <Field label="Duration (s)"><Input type="number" value={f.duration} onChange={(e) => set("duration", +e.target.value)} /></Field>
            <Field label="Rate profile"><Segmented value={f.profile} onChange={(v) => set("profile", v)} options={["constant", "ramp", "sine", "step"].map((v) => ({ value: v, label: v }))} /></Field>
            <Field label={`Per-bot jitter ±${Math.round(f.jitter * 100)}%`}><input type="range" min={0} max={0.6} step={0.05} value={f.jitter} onChange={(e) => set("jitter", +e.target.value)} className="mt-2 accent-[rgb(var(--accent))]" /></Field>
            <Field label="Staggered join (s)"><Input type="number" min={0} value={f.stagger} onChange={(e) => set("stagger", +e.target.value)} /></Field>
            <div className="flex items-center gap-4 sm:col-span-full">
              <Switch checked={f.burst} onCheckedChange={(v) => set("burst", v)} label="Pulsing (on/off)" />
              {f.burst && <>
                <Field label="On (s)"><Input type="number" step={0.5} value={f.on} onChange={(e) => set("on", +e.target.value)} className="w-24" /></Field>
                <Field label="Off (s)"><Input type="number" step={0.5} value={f.off} onChange={(e) => set("off", +e.target.value)} className="w-24" /></Field>
              </>}
            </div>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Defence" />
          <CardBody className="space-y-4">
            <Field label="Detector"><Select value={f.detector} onChange={(e) => set("detector", e.target.value)}>{(health.data?.detectors_loaded ?? []).map((d) => <option key={d} value={d}>{label(d)}</option>)}</Select></Field>
            <Field label="Approval mode"><Segmented value={f.mode} onChange={(v) => set("mode", v)} options={[{ value: "auto", label: "auto" }, { value: "hybrid", label: "hybrid" }, { value: "manual", label: "manual" }]} /></Field>
            <div className="rounded-md bg-raised p-3 text-xs text-muted">
              Offered attack load ≈ <b className="num text-fg">{fmt.num((f.pps * f.bots * 512 * 8) / 1e6, 1)} Mbit/s</b> against a 20 Mbit/s uplink.
            </div>
            <Button variant="primary" className="w-full" onClick={() => launch.mutate()} disabled={!can(role, "operator") || launch.isPending}><Swords /> Launch campaign</Button>
            {launch.error && <p className="text-xs text-bad">{String(launch.error.message)}</p>}
          </CardBody>
        </Card>
      </div>
    </>
  );
}

/* --------------------------------------------------------------- Topologies */
export function Topologies() {
  const q = useQuery({ queryKey: ["topologies"], queryFn: api.topologies });
  return (
    <>
      <PageHeader title="Topologies" subtitle="Seven families, each varying one structural assumption of the baseline tree." />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {(q.data ?? []).map((t) => (
          <Card key={t.name}>
            <CardHeader title={<span className="font-mono">{t.name}</span>} />
            <CardBody>
              <p className="text-sm text-muted">{t.description}</p>
              {Object.keys(t.parameters ?? {}).length > 0 && (
                <div className="mt-3 flex flex-wrap gap-1.5">{Object.entries(t.parameters).map(([k, v]) => <Badge key={k}>{k}: {String(v)}</Badge>)}</div>
              )}
            </CardBody>
          </Card>
        ))}
      </div>
    </>
  );
}

/* --------------------------------------------------------------- Policy */
export function Policy() {
  const role = useAuth((s) => s.role);
  const live = useUI((s) => s.live);
  const qc = useQueryClient();
  const policy = useQuery({ queryKey: ["policy"], queryFn: api.policy, refetchInterval: 5000 });
  const audit = useQuery({ queryKey: ["audit"], queryFn: api.audit, enabled: can(role, "admin"), retry: false });
  const setMode = useMutation({ mutationFn: api.setPolicy, onSuccess: () => qc.invalidateQueries({ queryKey: ["policy"] }) });
  const p = policy.data ?? ({} as any);
  return (
    <>
      <PageHeader title="Policy & audit" subtitle="The response ladder, the human-in-the-loop setting, and a tamper-evident record of every action." />
      <div className="grid gap-5 xl:grid-cols-[420px_1fr]">
        <Card>
          <CardHeader title="Response ladder" />
          <CardBody className="space-y-4 text-sm">
            <Field label="Approval mode" hint={live?.state === "running" ? "Applies to the running simulation immediately" : "Start a run to change it live"}>
              <Segmented value={p.approval_mode ?? "auto"} onChange={(v) => setMode.mutate(v)} options={[{ value: "auto", label: "automatic" }, { value: "hybrid", label: "hybrid" }, { value: "manual", label: "manual" }]} />
            </Field>
            <DataTable>
              <tbody>
                <tr><td>Trigger</td><td className="num">p ≥ {p.trigger_probability}</td></tr>
                <tr><td>Rate-limit</td><td className="num">p ≥ {p.rate_limit_probability} → {p.rate_limit_pps} pps</td></tr>
                <tr><td>Block</td><td className="num">p ≥ {p.block_probability}</td></tr>
                <tr><td>Isolate</td><td className="num">p ≥ {p.isolate_probability} for {p.escalation_windows} windows</td></tr>
                <tr><td>Release</td><td className="num">after {p.release_after_clean_windows} clean windows</td></tr>
              </tbody>
            </DataTable>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Audit trail" subtitle={audit.data ? (audit.data.chain_valid ? "Hash chain verified" : "Hash chain BROKEN") : "Admins only"}
            actions={audit.data && <Badge tone={audit.data.chain_valid ? "good" : "bad"}>{audit.data.chain_valid ? "intact" : "tampered"}</Badge>} />
          {audit.data ? (
            <div className="scroll-thin max-h-[520px] overflow-y-auto">
              <DataTable>
                <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Target</th><th>Outcome</th></tr></thead>
                <tbody>{audit.data.entries.map((e) => (
                  <tr key={e.id}><td className="num text-xs">{new Date(e.ts * 1000).toLocaleTimeString()}</td><td className="text-xs">{e.actor} <span className="text-subtle">({e.role || "–"})</span></td>
                    <td className="font-mono text-xs">{e.action}</td><td className="font-mono text-xs">{e.target}</td><td><Badge tone={String(e.outcome).startsWith("2") || e.outcome === "ok" ? "good" : "warn"}>{e.outcome}</Badge></td></tr>))}</tbody>
              </DataTable>
            </div>
          ) : <EmptyState icon={<Lock />} title="Audit trail is restricted" hint="Sign in as an admin, or run with authentication disabled for local development." />}
        </Card>
      </div>
    </>
  );
}
