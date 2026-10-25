import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, CustomChart, HeatmapChart, LineChart, ScatterChart } from "echarts/charts";
import {
  BrushComponent, DataZoomComponent, GridComponent, LegendComponent, MarkAreaComponent,
  MarkLineComponent, TitleComponent, ToolboxComponent, TooltipComponent, VisualMapComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { useUI } from "@/lib/store";
import { token } from "@/lib/utils";

echarts.use([
  LineChart, BarChart, ScatterChart, HeatmapChart, CustomChart, TitleComponent, GridComponent, TooltipComponent, LegendComponent,
  DataZoomComponent, MarkLineComponent, MarkAreaComponent, BrushComponent, ToolboxComponent,
  VisualMapComponent, CanvasRenderer,
]);

export type EOption = echarts.EChartsCoreOption;

/** Series palette, validated for contrast on both themes. */
export const SERIES = ["#2563eb", "#f97316", "#16a34a", "#9333ea", "#0891b2", "#e11d48", "#ca8a04", "#64748b"];

/** Theme-aware base options shared by every chart. */
export function baseOption(): EOption {
  const fg = token("muted");
  const grid = token("border");
  return {
    animation: false,
    color: SERIES,
    textStyle: { fontFamily: "Inter, system-ui, sans-serif", color: fg, fontSize: 11 },
    grid: { left: 48, right: 16, top: 24, bottom: 28, containLabel: false },
    tooltip: {
      trigger: "axis",
      backgroundColor: token("raised"),
      borderColor: grid,
      textStyle: { color: token("fg"), fontSize: 12 },
      axisPointer: { type: "line", lineStyle: { color: token("subtle") } },
    },
    xAxis: { axisLine: { lineStyle: { color: grid } }, axisLabel: { color: fg }, splitLine: { show: false } },
    yAxis: { axisLine: { show: false }, axisLabel: { color: fg }, splitLine: { lineStyle: { color: grid, type: "dashed" } } },
  };
}

const merge = (a: any, b: any): any => {
  if (Array.isArray(b) || typeof b !== "object" || b === null) return b;
  const out = { ...a };
  for (const k of Object.keys(b)) out[k] = k in a && typeof a[k] === "object" && !Array.isArray(a[k]) ? merge(a[k], b[k]) : b[k];
  return out;
};

export function Chart({ option, height = 220, group, onBrush, className }: {
  option: EOption; height?: number; group?: string; onBrush?: (range: [number, number] | null) => void; className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const inst = useRef<echarts.ECharts>();
  const dark = useUI((s) => s.dark);

  useEffect(() => {
    if (!ref.current) return;
    inst.current = echarts.init(ref.current, undefined, { renderer: "canvas" });
    if (group) {
      inst.current.group = group;
      echarts.connect(group);
    }
    const ro = new ResizeObserver(() => inst.current?.resize());
    ro.observe(ref.current);
    return () => {
      ro.disconnect();
      inst.current?.dispose();
    };
  }, [group]);

  useEffect(() => {
    inst.current?.setOption(merge(baseOption(), option), { notMerge: true });
  }, [option, dark]);

  useEffect(() => {
    if (!onBrush || !inst.current) return;
    const handler = (e: any) => {
      const z = e.batch?.[0] ?? e;
      if (z.start === 0 && z.end === 100) onBrush(null);
      else if (z.startValue != null) onBrush([z.startValue, z.endValue]);
    };
    inst.current.on("datazoom", handler);
    return () => {
      inst.current?.off("datazoom", handler);
    };
  }, [onBrush]);

  return <div ref={ref} className={className} style={{ height, width: "100%" }} />;
}

export function Sparkline({ data, color = SERIES[0], height = 34 }: { data: number[]; color?: string; height?: number }) {
  const option: EOption = {
    grid: { left: 0, right: 0, top: 2, bottom: 2 },
    tooltip: { show: false },
    xAxis: { type: "category", show: false, data: data.map((_, i) => i) },
    yAxis: { type: "value", show: false, scale: true },
    series: [{ type: "line", data, smooth: true, symbol: "none", lineStyle: { width: 1.6, color },
               areaStyle: { color, opacity: 0.12 } }],
  };
  return <Chart option={option} height={height} />;
}
