import { useMemo } from "react";
import type { IncidentEvent, WindowPoint } from "@/lib/types";
import { Chart, SERIES, type EOption } from "./Chart";

const EVENT_STYLE: Record<IncidentEvent["kind"], { colour: string; short: string }> = {
  attack_start: { colour: "#e11d48", short: "attack" },
  attack_end: { colour: "#e11d48", short: "end" },
  first_detection: { colour: "#ca8a04", short: "detected" },
  first_mitigation: { colour: "#9333ea", short: "mitigated" },
  recovered: { colour: "#16a34a", short: "recovered" },
};

function markers(events: IncidentEvent[], withLabels: boolean) {
  const start = events.find((e) => e.kind === "attack_start")?.t;
  const end = events.find((e) => e.kind === "attack_end")?.t;
  return {
    markLine: {
      silent: true, symbol: "none",
      data: events.map((e) => ({
        xAxis: e.t,
        lineStyle: { color: EVENT_STYLE[e.kind].colour, type: e.kind === "attack_end" ? "dotted" : "dashed", width: 1.2 },
        label: { show: withLabels, formatter: EVENT_STYLE[e.kind].short, color: EVENT_STYLE[e.kind].colour, fontSize: 10, position: "insideEndTop" },
      })),
    },
    markArea: start != null ? {
      silent: true, itemStyle: { color: "rgba(225,29,72,0.07)" },
      data: [[{ xAxis: start }, { xAxis: end ?? start }]],
    } : undefined,
  };
}

const panel = (title: string, unit: string, series: any[], opts: Partial<EOption> = {}): EOption => ({
  title: { text: title, left: 0, top: 0, textStyle: { fontSize: 12, fontWeight: 600 } },
  grid: { left: 52, right: 16, top: 30, bottom: 22 },
  legend: { top: 0, right: 0, itemWidth: 10, itemHeight: 6, textStyle: { fontSize: 11 } },
  xAxis: { type: "value", min: "dataMin", max: "dataMax", axisLabel: { formatter: "{value}s" } },
  yAxis: { type: "value", name: unit, nameTextStyle: { fontSize: 10 } },
  dataZoom: [{ type: "inside", xAxisIndex: 0, filterMode: "none" }],
  series,
  ...opts,
});

/** Four synced panels: availability, latency, traffic mix, detections and rules. */
export function IncidentTimeline({ windows, events, compact = false }: {
  windows: WindowPoint[]; events: IncidentEvent[]; compact?: boolean;
}) {
  const options = useMemo(() => {
    const x = (w: WindowPoint) => w.t_end;
    const line = (name: string, data: Array<[number, number | undefined]>, colour: string, extra: object = {}) => ({
      name, type: "line", data, symbol: "none", lineStyle: { width: 1.8, color: colour }, itemStyle: { color: colour }, ...extra,
    });
    const avail = panel("Service availability (clean devices)", "", [
      line("availability", windows.map((w) => [x(w), w.clean_availability]), SERIES[2], { areaStyle: { opacity: 0.08 }, ...markers(events, true) }),
      line("fairness", windows.map((w) => [x(w), w.clean_fairness]), SERIES[4], { lineStyle: { width: 1.2, type: "dashed", color: SERIES[4] } }),
    ], { yAxis: { type: "value", min: 0, max: 1, axisLabel: { formatter: (v: number) => `${Math.round(v * 100)}%` } } });
    const latency = panel("One-way latency, clean devices", "ms", [
      line("p50", windows.map((w) => [x(w), w.clean_p50_latency_ms]), SERIES[0], markers(events, false)),
      line("p99", windows.map((w) => [x(w), w.clean_p99_latency_ms]), SERIES[1]),
      line("jitter", windows.map((w) => [x(w), w.clean_jitter_ms]), SERIES[7], { lineStyle: { width: 1, type: "dotted", color: SERIES[7] } }),
    ]);
    const traffic = panel("Uplink traffic", "Mbit/s", [
      line("offered", windows.map((w) => [x(w), w.offered_mbps]), SERIES[5], { areaStyle: { opacity: 0.1 }, ...markers(events, false) }),
      line("delivered", windows.map((w) => [x(w), w.throughput_mbps]), SERIES[0]),
    ]);
    const defence = panel("Detections and mitigation", "", [
      { name: "flagged nodes", type: "bar", data: windows.map((w) => [x(w), w.flagged_nodes ?? 0]), itemStyle: { color: SERIES[6] }, barMaxWidth: 10, ...markers(events, false) },
      line("nodes under rule", windows.map((w) => [x(w), w.mitigated_sources]), SERIES[3]),
      line("collateral %", windows.map((w) => [x(w), (w.collateral_byte_ratio ?? 0) * 100]), SERIES[5], { lineStyle: { width: 1, type: "dashed", color: SERIES[5] } }),
    ]);
    return compact ? [avail, latency] : [avail, latency, traffic, defence];
  }, [windows, events, compact]);
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      {options.map((o, i) => <Chart key={i} option={o} height={compact ? 190 : 230} group="incident" />)}
    </div>
  );
}
