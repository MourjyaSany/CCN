import { Activity } from "lucide-react";
import { api } from "@/lib/api";
import { useLiveQuery } from "@/lib/live";
import { fmt } from "@/lib/utils";
import { IncidentTimeline } from "@/components/charts/Timeline";
import { Badge, Card, CardBody, CardHeader, DataTable, EmptyState, PageHeader, Skeleton } from "@/components/ui";

const KIND_TONE = { attack_start: "bad", attack_end: "neutral", first_detection: "warn", first_mitigation: "accent", recovered: "good" } as const;

export function Incidents() {
  const t = useLiveQuery("timeline", api.timeline);
  const w = t.data?.windows ?? [];
  const events = t.data?.events ?? [];
  const start = events.find((e) => e.kind === "attack_start")?.t;
  return (
    <>
      <PageHeader title="Incident timeline" subtitle="Every panel shares one time axis. Scroll or pinch on a chart to zoom all of them together." />
      <div className="grid gap-5 xl:grid-cols-[1fr_320px]">
        <Card>
          <CardHeader title={t.data?.scenario || "Current run"} subtitle={t.data?.run_id} />
          <CardBody>
            {t.isLoading ? <Skeleton className="h-[480px]" /> : w.length ? <IncidentTimeline windows={w} events={events} /> :
              <EmptyState icon={<Activity />} title="No incident data" hint="Run a scenario to populate the timeline, or open a saved run in Replay." />}
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Milestones" subtitle="Times relative to attack start" />
          <div className="divide-y divide-border">
            {events.map((e, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-3">
                <Badge tone={KIND_TONE[e.kind]}>{e.kind.replace("_", " ")}</Badge>
                <div className="flex-1 text-xs text-muted">{e.label}</div>
                <div className="num font-mono text-xs">{start != null && e.kind !== "attack_start" ? `+${(e.t - start).toFixed(1)}s` : fmt.s(e.t)}</div>
              </div>
            ))}
            {!events.length && <EmptyState title="No milestones yet" />}
          </div>
          {t.data?.mitigations?.length ? (
            <>
              <CardHeader title="Actions" className="border-t" />
              <DataTable>
                <thead><tr><th>t</th><th>Node</th><th>Action</th></tr></thead>
                <tbody>{t.data.mitigations.slice(-12).map((m, i) => (
                  <tr key={i}><td className="num text-xs">{fmt.s(m.timestamp)}</td><td className="font-mono text-xs">{m.node}</td>
                    <td><Badge tone={m.action === "release" ? "good" : "bad"}>{m.action}</Badge></td></tr>))}</tbody>
              </DataTable>
            </>
          ) : null}
        </Card>
      </div>
    </>
  );
}
