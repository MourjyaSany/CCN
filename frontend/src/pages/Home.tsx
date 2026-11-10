import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowRight, Cpu, MonitorPlay, Play, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { PipelineMap } from "@/components/home/PipelineMap";
import { Button } from "@/components/ui";

/** Short description of each pipeline stage, shown under the mindmap. */
const STAGES = [
  { k: "Topologies", c: "167 139 250", d: "Seven hierarchical families — tree, star, mesh, fat-tree, dumbbell, ring, multi-gateway — each wiring IoT end devices up through gateways to the cloud." },
  { k: "NS-3 engine", c: "46 200 224", d: "The real ns-3 discrete-event simulator builds the network and moves actual packets. Congestion and loss emerge from the topology, not from a formula." },
  { k: "Flow features", c: "245 185 70", d: "Per-node, per-window statistics are derived from the packet flows — rates, fan-out, entropy — exactly the signals a GNN needs to reason over the graph." },
  { k: "GNN detector", c: "96 165 250", d: "A graph neural network scores every node's probability of being hostile each window, learning from its neighbours, not just its own traffic." },
  { k: "Mitigation", c: "52 211 153", d: "When a node crosses the trigger, the gateway rate-limits, blocks or isolates it — in-band, so throughput recovering is a measured consequence, never asserted." },
  { k: "Visualise", c: "244 114 182", d: "Watch it two ways: packet-by-packet in the NS-3 animator (NetAnim), or window-by-window in this console with live metrics and incident timelines." },
];

function StatusChip({ ok, label, icon: Icon }: { ok: boolean; label: string; icon: typeof Cpu }) {
  return (
    <span className={cn(
      "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-semibold",
      ok ? "border-good/40 bg-good/10 text-good" : "border-chrome-border bg-chrome-raised text-chrome-muted",
    )}>
      <Icon className="size-3" /> {label}
    </span>
  );
}

export function Home() {
  const health = useQuery({ queryKey: ["health"], queryFn: api.health });
  const ns3 = useQuery({ queryKey: ["ns3-status"], queryFn: api.ns3Status, retry: false });
  const detectors = health.data?.detectors_loaded ?? [];

  return (
    <div className="grid-dots-ink -mx-4 -my-6 min-h-[calc(100vh-3.5rem)] bg-chrome-bg px-4 py-8 text-chrome-fg sm:-mx-6 sm:px-6">
      <div className="mx-auto w-full max-w-[1200px]">
        {/* hero */}
        <div className="animate-riseIn">
          <div className="mono mb-3 inline-flex items-center gap-2 rounded-full border border-chrome-border bg-chrome-raised px-3 py-1 text-[11px] text-chrome-muted">
            <span className="size-1.5 animate-pulseDot rounded-full bg-chrome-accent" />
            closed-loop DDoS defence for IoT–cloud networks
          </div>
          <h1 className="max-w-3xl text-[32px] font-bold leading-[1.1] tracking-tight sm:text-[42px]">
            Simulate the attack. Detect it on the graph.{" "}
            <span className="text-chrome-accent text-glow">Fight back in the loop.</span>
          </h1>
          <p className="mt-4 max-w-2xl text-[15px] leading-relaxed text-chrome-muted">
            NetShield-GNN builds a real IoT network in ns-3, floods it with a botnet, and lets a graph
            neural network find the compromised devices and shut them down at the gateway — then measures
            whether the healthy fleet actually recovers. Every packet is simulated; nothing leaves this machine.
          </p>

          <div className="mt-6 flex flex-wrap items-center gap-3">
            <Button asChild variant="primary" size="lg">
              <Link to="/overview"><Play /> Run a scenario</Link>
            </Button>
            <Button asChild size="lg" className="border-chrome-border bg-chrome-raised text-chrome-fg hover:border-chrome-accent/50 hover:bg-chrome-raised">
              <Link to="/ns3"><MonitorPlay /> Open NS-3 &amp; NetAnim</Link>
            </Button>
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <StatusChip ok={!!ns3.data?.available} label={ns3.data?.available ? `NS-3 ${ns3.data.version}` : "NS-3 offline"} icon={Cpu} />
              <StatusChip ok={!!ns3.data?.netanim_available} label={ns3.data?.netanim_available ? "NetAnim ready" : "NetAnim absent"} icon={MonitorPlay} />
              <StatusChip ok={detectors.length > 0} label={detectors.length ? `${detectors.length} detectors` : "no detectors"} icon={ShieldCheck} />
            </div>
          </div>
        </div>

        {/* pipeline mindmap */}
        <div className="mt-10 rounded-2xl border border-chrome-border bg-chrome-surface/60 p-4 shadow-chrome sm:p-6">
          <div className="mb-1 flex items-center justify-between">
            <div>
              <div className="label text-chrome-subtle">The pipeline</div>
              <div className="text-sm text-chrome-muted">How a run flows end to end — click any stage to jump in.</div>
            </div>
            <Link to="/about" className="hidden items-center gap-1 text-xs text-chrome-accent hover:underline sm:flex">
              How it works <ArrowRight className="size-3" />
            </Link>
          </div>
          <PipelineMap />
        </div>

        {/* stage explainers */}
        <div className="mt-8 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {STAGES.map((s) => (
            <div key={s.k} className="rounded-xl border border-chrome-border bg-chrome-surface/50 p-4 transition-colors hover:border-white/15">
              <div className="mb-1.5 flex items-center gap-2">
                <span className="size-2.5 rounded-full" style={{ background: `rgb(${s.c})`, boxShadow: `0 0 10px 0 rgb(${s.c} / 0.7)` }} />
                <span className="text-[13px] font-semibold text-chrome-fg">{s.k}</span>
              </div>
              <p className="text-[12.5px] leading-relaxed text-chrome-muted">{s.d}</p>
            </div>
          ))}
        </div>

        <p className="mono mt-8 text-center text-[11px] text-chrome-subtle">
          ns-3 · GraphSAGE / temporal-GNN · token-bucket mitigation · NetAnim — a research console, not a product.
        </p>
      </div>
    </div>
  );
}
