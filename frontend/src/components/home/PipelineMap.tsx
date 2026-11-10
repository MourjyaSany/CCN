import { useNavigate } from "react-router-dom";
import { Boxes, Cpu, GitBranch, MonitorPlay, ShieldCheck, Waypoints } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * The pipeline mindmap on the home page. A directed graph of the six stages
 * the project runs end to end, drawn as an SVG edge layer (flowing energy +
 * travelling packets) with interactive HTML node cards on top. The feedback
 * arc from Mitigation back into the NS-3 engine is the closed loop: rules
 * installed by the detector change what the live simulation does next.
 *
 * Coordinates live in an 960x380 viewBox; node cards are positioned over the
 * SVG by converting each centre to a percentage, so the whole thing scales.
 */

type Stage = {
  id: string; cx: number; cy: number; label: string; sub: string;
  icon: LucideIcon; color: string; to: string; step: string;
};

const W = 960, H = 380;

const STAGES: Stage[] = [
  { id: "topo", cx: 120, cy: 120, step: "01", label: "Topologies", sub: "IoT → gateway → cloud", icon: Waypoints, color: "167 139 250", to: "/topologies" },
  { id: "ns3", cx: 360, cy: 120, step: "02", label: "NS-3 engine", sub: "packet-level simulation", icon: Cpu, color: "46 200 224", to: "/ns3" },
  { id: "feat", cx: 600, cy: 120, step: "03", label: "Flow features", sub: "per-node, per-window", icon: GitBranch, color: "245 185 70", to: "/research" },
  { id: "gnn", cx: 840, cy: 120, step: "04", label: "GNN detector", sub: "P(hostile) per node", icon: Boxes, color: "96 165 250", to: "/alerts" },
  { id: "mit", cx: 840, cy: 280, step: "05", label: "Mitigation", sub: "rate-limit · block · isolate", icon: ShieldCheck, color: "52 211 153", to: "/mitigations" },
  { id: "viz", cx: 360, cy: 280, step: "06", label: "Visualise", sub: "NetAnim + this console", icon: MonitorPlay, color: "244 114 182", to: "/network" },
];

type Edge = { id: string; d: string; feedback?: boolean };

// center-to-center paths; node cards sit on top and hide the endpoints.
const EDGES: Edge[] = [
  { id: "e1", d: "M120,120 L360,120" },
  { id: "e2", d: "M360,120 L600,120" },
  { id: "e3", d: "M600,120 L840,120" },
  { id: "e4", d: "M840,120 L840,280" },
  { id: "e5", d: "M840,280 L360,280" },
  { id: "e6", d: "M360,120 L360,280" },
  { id: "fb", d: "M840,255 C 895,15 400,10 360,92", feedback: true },
];

export function PipelineMap() {
  const navigate = useNavigate();
  return (
    <div className="relative w-full" style={{ aspectRatio: `${W} / ${H}` }}>
      <svg viewBox={`0 0 ${W} ${H}`} className="absolute inset-0 h-full w-full" preserveAspectRatio="xMidYMid meet" aria-hidden>
        <defs>
          <linearGradient id="edgeFade" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stopColor="rgb(var(--chrome-accent))" stopOpacity="0.15" />
            <stop offset="100%" stopColor="rgb(var(--chrome-accent))" stopOpacity="0.5" />
          </linearGradient>
          <filter id="soft"><feGaussianBlur stdDeviation="2.2" /></filter>
        </defs>

        {EDGES.map((e) => (
          <g key={e.id}>
            {/* base rail */}
            <path d={e.d} fill="none"
              stroke={e.feedback ? "rgb(52 211 153)" : "rgb(var(--chrome-accent))"}
              strokeOpacity={e.feedback ? 0.3 : 0.22} strokeWidth={e.feedback ? 2 : 3} strokeLinecap="round" />
            {/* flowing energy */}
            <path d={e.d} fill="none"
              stroke={e.feedback ? "rgb(52 211 153)" : "rgb(var(--chrome-accent))"}
              strokeOpacity={0.9} strokeWidth={e.feedback ? 2 : 2.4} strokeLinecap="round"
              className="flow-dash" style={e.feedback ? { animationDuration: "1.5s" } : undefined} />
            {/* travelling packet */}
            <circle r={e.feedback ? 2.6 : 3.4} fill={e.feedback ? "rgb(52 211 153)" : "rgb(var(--chrome-accent))"} filter="url(#soft)">
              <animateMotion dur={e.feedback ? "3.6s" : "2.4s"} repeatCount="indefinite" path={e.d} />
            </circle>
          </g>
        ))}

        {/* feedback label */}
        <text x="600" y="34" textAnchor="middle" className="mono" fontSize="12"
          fill="rgb(52 211 153)" opacity="0.85">closed-loop enforcement</text>
      </svg>

      {/* node cards */}
      {STAGES.map((s, i) => (
        <button
          key={s.id}
          onClick={() => navigate(s.to)}
          style={{
            left: `${(s.cx / W) * 100}%`, top: `${(s.cy / H) * 100}%`,
            ["--c" as string]: `rgb(${s.color})`,
            animationDelay: `${i * 90}ms`,
          }}
          className={cn(
            "press animate-riseIn group absolute flex w-[clamp(118px,15vw,168px)] -translate-x-1/2 -translate-y-1/2 flex-col gap-1.5",
            "rounded-xl border border-white/10 bg-chrome-raised/90 p-3 text-left backdrop-blur-sm",
            "shadow-chrome transition-all duration-200 hover:-translate-y-[calc(50%+3px)] hover:border-[color:var(--c)]",
            "hover:shadow-[0_0_26px_-6px_var(--c)]",
          )}
        >
          <div className="flex items-center justify-between">
            <span className="grid size-8 place-items-center rounded-lg ring-1 ring-white/10"
              style={{ background: `rgb(${s.color} / 0.14)` }}>
              <s.icon className="size-4" style={{ color: `rgb(${s.color})` }} />
            </span>
            <span className="mono text-[10px] font-semibold tracking-wider text-chrome-subtle">{s.step}</span>
          </div>
          <div className="text-[13px] font-semibold leading-tight text-chrome-fg">{s.label}</div>
          <div className="mono text-[10px] leading-tight text-chrome-muted">{s.sub}</div>
          <span className="pointer-events-none absolute -bottom-px left-3 right-3 h-px opacity-0 transition-opacity group-hover:opacity-100"
            style={{ background: `linear-gradient(90deg, transparent, var(--c), transparent)` }} />
        </button>
      ))}
    </div>
  );
}
