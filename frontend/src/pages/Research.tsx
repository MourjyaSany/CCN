import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { FileBarChart } from "lucide-react";
import { api } from "@/lib/api";
import { fmt, label } from "@/lib/utils";
import { Chart, SERIES, type EOption } from "@/components/charts/Chart";
import {
  Badge, Card, CardBody, CardHeader, DataTable, EmptyState, PageHeader, Skeleton, Tabs, TabsContent,
  TabsList, TabsTrigger,
} from "@/components/ui";

const n = (v: any) => (typeof v === "number" ? v : v == null ? NaN : Number(v));

function Forest({ rows, metric, title }: { rows: any[]; metric: string; title: string }) {
  const sorted = rows.slice().sort((a, b) => n(a[metric]) - n(b[metric]));
  const option: EOption = {
    grid: { left: 140, right: 64, top: 28, bottom: 28 },
    title: { text: title, textStyle: { fontSize: 12, fontWeight: 600 } },
    tooltip: { trigger: "item", formatter: (p: any) => {
      const r = sorted[p.dataIndex];
      return `${label(r.variant)}<br/>${n(r[metric]).toFixed(4)} [${n(r[`${metric}_lo`]).toFixed(4)}, ${n(r[`${metric}_hi`]).toFixed(4)}]`;
    } },
    xAxis: { type: "value", scale: true },
    yAxis: { type: "category", data: sorted.map((r) => label(r.variant)), axisLabel: { fontSize: 11 } },
    series: [
      { type: "custom" as any, renderItem: (_: any, api: any) => {
          const y = api.value(2), lo = api.coord([api.value(0), y]), hi = api.coord([api.value(1), y]);
          return { type: "line", shape: { x1: lo[0], y1: lo[1], x2: hi[0], y2: hi[1] }, style: { stroke: SERIES[0], lineWidth: 2 } };
        }, data: sorted.map((r, i) => [n(r[`${metric}_lo`]), n(r[`${metric}_hi`]), i]), encode: { x: [0, 1], y: 2 } },
      { type: "scatter", data: sorted.map((r) => n(r[metric])), symbolSize: 9, itemStyle: { color: SERIES[0] },
        label: { show: true, position: "right", formatter: (p: any) => n(p.value).toFixed(3), fontSize: 10 } },
    ],
  };
  return <Chart option={option} height={44 + 30 * sorted.length} />;
}

function Heat({ rows, valueKey, title }: { rows: any[]; valueKey: string; title: string }) {
  const variants = [...new Set(rows.map((r) => r.variant))];
  const folds = [...new Set(rows.map((r) => r.fold))];
  const data = rows.map((r) => [folds.indexOf(r.fold), variants.indexOf(r.variant), n(r[valueKey])]);
  const vals = data.map((d) => d[2] as number).filter((v) => !Number.isNaN(v));
  const option: EOption = {
    grid: { left: 140, right: 70, top: 28, bottom: 64 },
    title: { text: title, textStyle: { fontSize: 12, fontWeight: 600 } },
    tooltip: { trigger: "item", formatter: (p: any) => `${label(variants[p.value[1]])} on ${folds[p.value[0]]}: ${n(p.value[2]).toFixed(3)}` },
    xAxis: { type: "category", data: folds, axisLabel: { rotate: 30, fontSize: 10 } },
    yAxis: { type: "category", data: variants.map(label), axisLabel: { fontSize: 11 } },
    visualMap: { min: Math.min(...vals), max: 1, calculable: false, orient: "vertical", right: 0, top: "middle",
                 inRange: { color: ["#fde68a", "#86efac", "#16a34a"] }, textStyle: { fontSize: 10 } },
    series: [{ type: "heatmap", data, label: { show: true, formatter: (p: any) => n(p.value[2]).toFixed(2), fontSize: 10 } }],
  };
  return <Chart option={option} height={110 + 30 * variants.length} />;
}

function Table({ rows, cols }: { rows: any[]; cols: Array<{ key: string; label: string; fmt?: (v: any, r: any) => React.ReactNode }> }) {
  return (
    <DataTable>
      <thead><tr>{cols.map((c) => <th key={c.key}>{c.label}</th>)}</tr></thead>
      <tbody>{rows.map((r, i) => <tr key={i}>{cols.map((c) => <td key={c.key} className="num text-xs">{c.fmt ? c.fmt(r[c.key], r) : String(r[c.key] ?? "–")}</td>)}</tr>)}</tbody>
    </DataTable>
  );
}

const ci = (r: any, m: string) => `${n(r[m]).toFixed(3)} [${n(r[`${m}_lo`]).toFixed(3)}, ${n(r[`${m}_hi`]).toFixed(3)}]`;

export function Research() {
  const q = useQuery({ queryKey: ["research"], queryFn: api.research });
  const [tab, setTab] = useState("cv");
  const t = q.data?.tables ?? {};
  const head = useMemo(() => (t.seed_cv_headline ?? []).filter((r: any) => !String(r.variant).startsWith("abl_")), [t]);
  if (q.isLoading) return <Skeleton className="h-96" />;
  if (!Object.keys(t).length) {
    return (
      <>
        <PageHeader title="Research results" />
        <Card><EmptyState icon={<FileBarChart />} title="No research results yet"
          hint={<>Run <code className="font-mono">python scripts/research_protocol.py analyse</code> after the protocol finishes.</>} /></Card>
      </>
    );
  }
  return (
    <>
      <PageHeader title="Research results"
        subtitle="Leave-one-seed-out cross-validation over every topology and attack family, with 95% run-level bootstrap intervals."
        note="Where the project earns its claims. Instead of a single demo run, detectors are scored across many seeds, topologies and attack families with proper confidence intervals — so a difference between two models is statistically defensible, not cherry-picked."
        actions={q.data?.report_available && <Badge tone="good">full report: results/reports/RESEARCH_RESULTS.md</Badge>} />
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="cv">Detection</TabsTrigger>
          <TabsTrigger value="general">Generalisation</TabsTrigger>
          <TabsTrigger value="stress">False alarms</TabsTrigger>
          <TabsTrigger value="loop">Closed loop</TabsTrigger>
          <TabsTrigger value="adv">Adversary</TabsTrigger>
          <TabsTrigger value="real">Real traffic</TabsTrigger>
        </TabsList>
        <TabsContent value="cv">
          <div className="grid gap-5 xl:grid-cols-2">
            <Card><CardBody><Forest rows={head} metric="macro_f1" title="Macro-F1 with 95% CI" /></CardBody></Card>
            <Card><CardBody><Forest rows={head} metric="hostile_pr_auc" title="PR-AUC (hostile) with 95% CI" /></CardBody></Card>
          </div>
          <Card className="mt-5">
            <CardHeader title="All detectors" subtitle="Pooled out-of-fold predictions" />
            <Table rows={head.slice().sort((a: any, b: any) => b.macro_f1 - a.macro_f1)} cols={[
              { key: "variant", label: "Detector", fmt: (v) => <span className="font-sans font-medium">{label(v)}</span> },
              { key: "macro_f1", label: "Macro-F1", fmt: (_, r) => ci(r, "macro_f1") },
              { key: "mcc", label: "MCC", fmt: (_, r) => ci(r, "mcc") },
              { key: "tpr_at_fpr_0.01", label: "Recall @1% FPR", fmt: (_, r) => ci(r, "tpr_at_fpr_0.01") },
              { key: "false_positive_rate", label: "FPR", fmt: (v) => fmt.pct(n(v), 2) },
              { key: "hostile_ece", label: "ECE", fmt: (v) => n(v).toFixed(4) },
              { key: "f1_suspicious", label: "F1 suspicious", fmt: (v) => n(v).toFixed(3) },
            ]} />
          </Card>
          {t.seed_cv_comparisons?.length ? (
            <Card className="mt-5">
              <CardHeader title="Is GraphSAGE better?" subtitle="Paired run-level bootstrap, Holm-corrected" />
              <Table rows={t.seed_cv_comparisons} cols={[
                { key: "other", label: "vs", fmt: label },
                { key: "metric", label: "Metric" },
                { key: "diff", label: "Difference", fmt: (v, r) => `${n(v) >= 0 ? "+" : ""}${n(v).toFixed(4)} [${n(r.lo).toFixed(4)}, ${n(r.hi).toFixed(4)}]` },
                { key: "p_holm", label: "p (Holm)", fmt: (v) => n(v).toFixed(4) },
                { key: "significant", label: "", fmt: (v) => (String(v) === "true" || v === true) ? <Badge tone="good">significant</Badge> : <Badge>n.s.</Badge> },
              ]} />
            </Card>
          ) : null}
        </TabsContent>
        <TabsContent value="general">
          <div className="grid gap-5">
            {t.loto?.length ? <Card><CardBody><Heat rows={t.loto} valueKey="macro_f1" title="Leave-one-topology-out: macro-F1 on a topology never seen in training" /></CardBody></Card> : null}
            {t.loafo?.length ? <Card><CardBody><Heat rows={t.loafo} valueKey="hostile_pr_auc" title="Leave-one-attack-family-out: PR-AUC on an attack family never seen in training" /></CardBody></Card> : null}
            {!t.loto?.length && !t.loafo?.length && <Card><EmptyState title="Hold-out designs not run yet" /></Card>}
          </div>
        </TabsContent>
        <TabsContent value="stress">
          {t.stress?.length ? (
            <Card>
              <CardHeader title="Benign surges with no attack" subtitle="Every flag here is a false alarm" />
              <Table rows={t.stress} cols={[
                { key: "variant", label: "Detector", fmt: label }, { key: "scenario", label: "Scenario" },
                { key: "false_alarm_nodes_per_run", label: "Innocent devices flagged / run", fmt: (v) => n(v).toFixed(2) },
                { key: "window_fpr", label: "Window FPR", fmt: (v) => fmt.pct(n(v), 2) },
                { key: "false_alarms_per_node_hour", label: "False alarms / device-hour", fmt: (v) => n(v).toFixed(1) },
              ]} />
            </Card>
          ) : <Card><EmptyState title="No stress results" /></Card>}
        </TabsContent>
        <TabsContent value="loop">
          {t.closed_loop_summary?.length ? (
            <Card>
              <CardHeader title="Each detector in charge of the gateway" subtitle="Unseen seeds; median times from attack start" />
              <Table rows={t.closed_loop_summary} cols={[
                { key: "detector", label: "Defence", fmt: label },
                { key: "availability_attack", label: "Availability under attack", fmt: (v) => fmt.pct(n(v)) },
                { key: "ttd_median_s", label: "Detect", fmt: (v) => fmt.s(n(v)) },
                { key: "ttm_median_s", label: "Mitigate", fmt: (v) => fmt.s(n(v)) },
                { key: "ttr_median_s", label: "Recover", fmt: (v) => fmt.s(n(v)) },
                { key: "collateral_byte_ratio", label: "Collateral", fmt: (v) => fmt.pct(n(v), 2) },
                { key: "mitigation_precision", label: "Rule precision", fmt: (v) => n(v).toFixed(3) },
                { key: "wrongly_mitigated", label: "Innocents ruled", fmt: (v) => fmt.num(n(v)) },
                { key: "stress_false_alarm_nodes", label: "Stress false alarms", fmt: (v) => n(v).toFixed(2) },
              ]} />
            </Card>
          ) : <Card><EmptyState title="Closed-loop evaluation not run yet" /></Card>}
        </TabsContent>
        <TabsContent value="adv">
          {t.adversary_summary?.length ? (
            <Card>
              <CardHeader title="Adaptive adversary (Bayesian search against each defence)" subtitle="Evasive = breaks the SLO while no bot is ever flagged" />
              <Table rows={t.adversary_summary} cols={[
                { key: "search", label: "Search" }, { key: "trials", label: "Attacks tried" },
                { key: "evasion_success_rate", label: "Evasion success", fmt: (v) => fmt.pct(n(v)) },
                { key: "max_undetected_damage", label: "Max undetected damage", fmt: (v) => fmt.pct(n(v)) },
                { key: "max_damage", label: "Max damage", fmt: (v) => fmt.pct(n(v)) },
                { key: "min_undetected_volume_for_slo", label: "Stealth threshold", fmt: (v) => Number.isNaN(n(v)) ? "never" : `${n(v).toFixed(2)} Mbit/s` },
                { key: "frontier_area", label: "Frontier area", fmt: (v) => n(v).toFixed(3) },
              ]} />
            </Card>
          ) : <Card><EmptyState title="Adversary search not run yet" /></Card>}
        </TabsContent>
        <TabsContent value="real">
          {t.real_data?.length ? (
            <Card>
              <CardHeader title="CICIoT2023 packet captures" subtitle="Models trained only in simulation, scored on real IoT traffic" />
              <Table rows={t.real_data} cols={[
                { key: "capture", label: "Capture" }, { key: "detector", label: "Detector", fmt: label },
                { key: "hosts", label: "Hosts" }, { key: "windows", label: "Windows" },
                { key: "host_window_flag_rate", label: "Host-window flag rate", fmt: (v) => fmt.pct(n(v), 2) },
                { key: "windows_with_flag", label: "Windows with a flag", fmt: (v) => fmt.pct(n(v)) },
                { key: "flagged_hosts", label: "Hosts flagged" },
                { key: "flagged_hosts_packet_share", label: "Their packet share", fmt: (v) => fmt.pct(n(v)) },
              ]} />
            </Card>
          ) : <Card><EmptyState title="Real-traffic evaluation not run yet" /></Card>}
        </TabsContent>
      </Tabs>
      {q.data?.figures.length ? (
        <Card className="mt-5">
          <CardHeader title="Figures" />
          <CardBody className="grid gap-4 md:grid-cols-2">
            {q.data.figures.map((f) => <img key={f} src={`/api/figures/${f}`} alt={f} className="w-full rounded-md border border-border bg-white" loading="lazy" />)}
          </CardBody>
        </Card>
      ) : null}
    </>
  );
}
