import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/store";
import { Badge, Button, Card, CardBody, CardHeader, Field, Input, PageHeader } from "@/components/ui";

const STAGES = [
  ["Generate", "Packet-level discrete-event simulator: 7 topologies, 6 attack families, benign surges, an adaptive adversary."],
  ["Observe", "IPFIX-style flow export (RFC 7011) to 46 node-window features and a communication graph."],
  ["Decide", "GraphSAGE / temporal GNN with calibrated, conformal decisions, explained by integrated gradients."],
  ["Act", "Rate-limit, block, isolate at the ingress port: OpenFlow, nftables or P4 rules, with human approval."],
];

export function About() {
  return (
    <>
      <PageHeader title="About NetShield-GNN" subtitle="Closed-loop DDoS detection and mitigation for IoT-cloud networks." />
      <div className="grid gap-5 xl:grid-cols-2">
        <Card>
          <CardHeader title="The loop" />
          <CardBody>
            <ol className="relative space-y-4 border-l border-border pl-5">
              {STAGES.map(([t, d], i) => (
                <li key={t}>
                  <span className="absolute -left-[9px] flex size-[18px] items-center justify-center rounded-full bg-accent text-[10px] font-bold text-white">{i + 1}</span>
                  <div className="text-sm font-semibold">{t}</div>
                  <p className="text-sm text-muted">{d}</p>
                </li>
              ))}
            </ol>
            <p className="mt-4 text-xs text-muted">Mitigation is enforced inside the packet path, so a rule installed at t = 40 s changes the run from t = 40 s onwards. Recovery is measured, not asserted.</p>
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Threat model and safety" />
          <CardBody className="space-y-3 text-sm text-muted">
            <p>The adversary controls compromised IoT devices and chooses the attack family, rate, shape, size and timing. It sees only how much damage each attempt did. It cannot compromise routers, the gateway or the cloud.</p>
            <p>The defender sees flow telemetry at the gateway and enforces rules on the physical ingress port, which address spoofing cannot forge.</p>
            <p><Badge tone="good">safe by construction</Badge> All attack traffic is generated inside an in-memory simulator. The testbed variant runs inside Mininet namespaces and refuses targets outside 10.0.0.0/8.</p>
          </CardBody>
        </Card>
        <Card className="xl:col-span-2">
          <CardHeader title="Documentation" />
          <CardBody className="flex flex-wrap gap-2">
            <Button asChild size="sm"><a href="/docs" target="_blank" rel="noreferrer">API reference (OpenAPI)</a></Button>
            <Button asChild size="sm"><a href="/metrics" target="_blank" rel="noreferrer">Prometheus metrics</a></Button>
            <Button asChild size="sm"><a href="/legacy">Legacy dashboard</a></Button>
          </CardBody>
        </Card>
      </div>
    </>
  );
}

export function Login() {
  const setSession = useAuth((s) => s.setSession);
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const t = await api.login(u, p);
      setSession(t.access_token, u, t.role);
    } catch (x: any) {
      setErr(x.message ?? "Sign-in failed");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex min-h-full items-center justify-center bg-bg p-4">
      <Card className="w-full max-w-sm">
        <CardBody className="space-y-5 p-6">
          <div className="flex items-center gap-3">
            <ShieldCheck className="size-8 text-accent" />
            <div><div className="font-semibold">NetShield-GNN</div><div className="text-xs text-muted">Sign in to the operations console</div></div>
          </div>
          <form onSubmit={submit} className="space-y-3">
            <Field label="Username"><Input autoFocus autoComplete="username" value={u} onChange={(e) => setU(e.target.value)} /></Field>
            <Field label="Password"><Input type="password" autoComplete="current-password" value={p} onChange={(e) => setP(e.target.value)} /></Field>
            {err && <p className="text-xs text-bad">{err}</p>}
            <Button variant="primary" className="w-full" disabled={busy || !u || !p}>Sign in</Button>
          </form>
        </CardBody>
      </Card>
    </div>
  );
}
