import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, ShieldCheck, ShieldOff, X } from "lucide-react";
import { api } from "@/lib/api";
import { useLiveQuery } from "@/lib/live";
import { can, useAuth } from "@/lib/store";
import { fmt } from "@/lib/utils";
import { Badge, Button, Card, CardHeader, DataTable, EmptyState, PageHeader } from "@/components/ui";

export function Mitigations() {
  const qc = useQueryClient();
  const role = useAuth((s) => s.role);
  const operator = can(role, "operator");
  const approvals = useLiveQuery("approvals", () => api.approvals("all"), 1500);
  const log = useLiveQuery("mitigation", () => api.mitigation(500));
  const topo = useLiveQuery("topology", api.topology);
  const policy = useLiveQuery("policy", api.policy);
  const done = () => qc.invalidateQueries();
  const approve = useMutation({ mutationFn: api.approve, onSuccess: done });
  const reject = useMutation({ mutationFn: api.reject, onSuccess: done });
  const rollback = useMutation({ mutationFn: api.rollback, onSuccess: done });
  const pending = (approvals.data ?? []).filter((a) => a.status === "pending");
  const active = (topo.data?.nodes ?? []).filter((n) => n.mitigation);
  return (
    <>
      <PageHeader title="Mitigations" subtitle="Rules at the gateway ingress, keyed on the physical port, so spoofed source addresses cannot dodge them."
        note="The defence acting on the detector's verdict. Each rule — rate-limit, block or isolate — is enforced in-band on the live packet path, so dropped traffic and recovering throughput are measured outcomes. Keyed on the ingress port, not the source IP, so address spoofing can't slip past."
        actions={<Badge tone="accent">approval mode: {policy.data?.approval_mode ?? "–"}</Badge>} />
      <div className="grid gap-5 xl:grid-cols-2">
        <Card>
          <CardHeader title="Waiting for approval" subtitle="In hybrid or manual mode, blocks and isolations queue here for an operator." />
          {pending.length ? (
            <DataTable>
              <thead><tr><th>Node</th><th>Action</th><th>p</th><th>Queued</th><th /></tr></thead>
              <tbody>{pending.map((a) => (
                <tr key={a.id}>
                  <td className="font-mono text-xs">{a.node}</td><td><Badge tone="bad">{a.action}</Badge></td>
                  <td className="num text-xs">{a.confidence.toFixed(3)}</td><td className="num text-xs">{fmt.s(a.timestamp)}</td>
                  <td className="text-right">
                    <div className="inline-flex gap-1.5">
                      <Button size="xs" variant="good" disabled={!operator} onClick={() => approve.mutate(a.id)}><Check /> Approve</Button>
                      <Button size="xs" variant="ghost" disabled={!operator} onClick={() => reject.mutate(a.id)}><X /> Reject</Button>
                    </div>
                  </td>
                </tr>))}</tbody>
            </DataTable>
          ) : <EmptyState icon={<ShieldCheck />} title="Nothing waiting" hint="Start a run in hybrid or manual approval mode to review actions before they apply." />}
        </Card>
        <Card>
          <CardHeader title="Active rules" subtitle={`${active.length} nodes currently restricted`} />
          {active.length ? (
            <DataTable>
              <thead><tr><th>Node</th><th>Rule</th><th>p</th><th /></tr></thead>
              <tbody>{active.map((n) => (
                <tr key={n.node_id}>
                  <td><span className="font-mono text-xs">{n.node_id}</span> {n.is_attacker ? <Badge tone="bad">bot</Badge> : <Badge tone="warn">clean device</Badge>}</td>
                  <td><Badge tone="bad">{n.mitigation}</Badge></td><td className="num text-xs">{n.probability.toFixed(3)}</td>
                  <td className="text-right"><Button size="xs" variant="ghost" disabled={!operator} onClick={() => rollback.mutate(n.node_id)}><ShieldOff /> Roll back</Button></td>
                </tr>))}</tbody>
            </DataTable>
          ) : <EmptyState title="No rules installed" />}
        </Card>
      </div>
      <Card className="mt-5">
        <CardHeader title="Action log" subtitle="Installs, escalations, releases, approvals and rollbacks" />
        {log.data?.length ? (
          <DataTable>
            <thead><tr><th>t</th><th>Node</th><th>Action</th><th>p</th><th>Reason</th></tr></thead>
            <tbody>{log.data.slice().reverse().map((m, i) => (
              <tr key={i}><td className="num text-xs">{fmt.s(m.timestamp)}</td><td className="font-mono text-xs">{m.node}</td>
                <td><Badge tone={m.action === "release" ? "good" : "bad"}>{m.action}</Badge></td>
                <td className="num text-xs">{m.confidence.toFixed(3)}</td><td className="text-xs text-muted">{m.reason}</td></tr>))}</tbody>
          </DataTable>
        ) : <EmptyState title="No actions yet" />}
      </Card>
    </>
  );
}
