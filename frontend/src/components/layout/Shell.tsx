import { useEffect, type ReactNode } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Command } from "cmdk";
import {
  Activity, BookOpen, Boxes, FlaskConical, GaugeCircle, History, Home, LayoutDashboard, LogOut,
  MonitorPlay, Moon, Network, Search, ShieldAlert, ShieldCheck, SlidersHorizontal, Sun, Swords, Waypoints,
} from "lucide-react";
import { api } from "@/lib/api";
import { useAuth, useUI } from "@/lib/store";
import { cn, fmt, label } from "@/lib/utils";
import { Badge, Button, StatusDot, Tip } from "@/components/ui";

export const NAV = [
  { group: "Operate", items: [
    { to: "/", label: "Home", icon: Home, key: "g h" },
    { to: "/overview", label: "Overview", icon: LayoutDashboard, key: "g o" },
    { to: "/network", label: "Live network", icon: Network, key: "g n" },
    { to: "/incidents", label: "Incident timeline", icon: Activity, key: "g i" },
    { to: "/alerts", label: "Alerts", icon: ShieldAlert, key: "g a" },
    { to: "/mitigations", label: "Mitigations", icon: ShieldCheck, key: "g m" },
  ] },
  { group: "Analyse", items: [
    { to: "/experiments", label: "Experiments", icon: FlaskConical, key: "g e" },
    { to: "/research", label: "Research results", icon: GaugeCircle, key: "g r" },
    { to: "/replay", label: "Replay", icon: History, key: "g p" },
    { to: "/ns3", label: "NS-3 & NetAnim", icon: MonitorPlay, key: "g 3" },
  ] },
  { group: "Configure", items: [
    { to: "/attack-builder", label: "Attack builder", icon: Swords, key: "g b" },
    { to: "/topologies", label: "Topologies", icon: Waypoints, key: "g t" },
    { to: "/policy", label: "Policy & audit", icon: SlidersHorizontal, key: "g y" },
    { to: "/about", label: "About", icon: BookOpen, key: "g ?" },
  ] },
];

function Sidebar() {
  return (
    <aside className="grid-dots relative hidden w-60 shrink-0 flex-col border-r border-chrome-border bg-chrome-bg text-chrome-fg lg:flex">
      {/* brand */}
      <div className="flex h-14 items-center gap-2.5 border-b border-chrome-border px-4">
        <div className="relative grid size-8 place-items-center rounded-md bg-chrome-raised ring-1 ring-chrome-accent/40">
          <img src="/app/shield.svg" alt="" className="size-5" />
          <span className="absolute inset-0 rounded-md shadow-[0_0_14px_-2px_rgb(var(--chrome-accent)/0.6)]" />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-semibold tracking-tight">NetShield<span className="text-chrome-accent">·</span>GNN</div>
          <div className="mono text-[10px] tracking-wide text-chrome-subtle">IoT DDoS defence console</div>
        </div>
      </div>

      <nav className="scroll-thin flex-1 overflow-y-auto px-2.5 py-3" aria-label="Main">
        {NAV.map((g) => (
          <div key={g.group} className="mb-4">
            <div className="px-2 pb-1.5 text-[10px] font-semibold uppercase tracking-[0.14em] text-chrome-subtle">{g.group}</div>
            {g.items.map((it) => (
              <NavLink
                key={it.to}
                to={it.to}
                end={it.to === "/"}
                className={({ isActive }) =>
                  cn(
                    "press group relative flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] transition-colors",
                    isActive
                      ? "bg-chrome-accent/10 font-medium text-chrome-accent"
                      : "text-chrome-muted hover:bg-white/[0.04] hover:text-chrome-fg",
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    {isActive && (
                      <span className="absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r-full bg-chrome-accent shadow-[0_0_10px_0_rgb(var(--chrome-accent)/0.8)]" />
                    )}
                    <it.icon className={cn("size-4 transition-colors", isActive ? "text-chrome-accent" : "text-chrome-subtle group-hover:text-chrome-fg")} />
                    {it.label}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      <div className="border-t border-chrome-border px-4 py-3">
        <div className="flex items-center gap-1.5 text-[10px] text-chrome-subtle">
          <StatusDot tone="good" />
          <span className="mono">sandboxed · no packet leaves this host</span>
        </div>
      </div>
    </aside>
  );
}

function Topbar() {
  const live = useUI((s) => s.live);
  const transport = useUI((s) => s.liveTransport);
  const { dark, toggleTheme, setPalette } = useUI();
  const { user, role, token, expire } = useAuth();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 30000 });
  const running = live?.state === "running";
  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-chrome-border bg-chrome-surface px-4 text-chrome-fg">
      <button
        onClick={() => setPalette(true)}
        className="press flex h-9 w-full max-w-sm items-center gap-2 rounded-md border border-chrome-border bg-chrome-raised px-3 text-sm text-chrome-subtle transition-colors hover:border-chrome-accent/40 hover:text-chrome-fg"
      >
        <Search className="size-4" />
        <span className="flex-1 text-left">Search pages, nodes, actions…</span>
        <kbd className="mono rounded border border-chrome-border px-1.5 text-[10px]">Ctrl K</kbd>
      </button>
      <div className="ml-auto flex items-center gap-3 text-xs">
        <Tip content={`Live feed via ${transport}`}>
          <span className="hidden items-center gap-1.5 text-chrome-muted md:flex">
            <StatusDot tone={transport === "offline" ? "bad" : running ? "good" : "neutral"} pulse={running} />
            {running ? (
              <span className="mono">
                {live?.scenario} · t={fmt.s(live?.sim_time_s)} / {fmt.s(live?.duration_s, 0)}
              </span>
            ) : (
              <span className="mono">{live?.state ?? "idle"}</span>
            )}
          </span>
        </Tip>
        {live?.detector && <Badge tone="accent">{label(live.detector)}</Badge>}
        {health.data && (
          <Tip content={`GNN backend ${health.data.gnn_backend} · NS-3 ${health.data.ns3_available ? "available" : "not installed"}`}>
            <span className={cn(
              "hidden items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-semibold sm:inline-flex",
              health.data.status === "ok"
                ? "border-good/30 bg-good/10 text-good"
                : "border-bad/30 bg-bad/10 text-bad",
            )}>
              <Boxes className="size-3" /> {health.data.engine.split("(")[0].trim()}
            </span>
          </Tip>
        )}
        <Button variant="ghost" size="icon" onClick={toggleTheme} aria-label="Toggle theme"
          className="text-chrome-muted hover:bg-white/[0.06] hover:text-chrome-fg">
          {dark ? <Sun /> : <Moon />}
        </Button>
        {token && (
          <Tip content={`${user} (${role})`}>
            <Button variant="ghost" size="icon" onClick={expire} aria-label="Sign out"
              className="text-chrome-muted hover:bg-white/[0.06] hover:text-chrome-fg"><LogOut /></Button>
          </Tip>
        )}
      </div>
    </header>
  );
}

export function CommandPalette() {
  const { paletteOpen, setPalette, selectNode, toggleTheme } = useUI();
  const navigate = useNavigate();
  const topo = useQuery({ queryKey: ["topology"], queryFn: api.topology, enabled: paletteOpen });
  useEffect(() => {
    let pending = "";
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette(!useUI.getState().paletteOpen);
        return;
      }
      const target = e.target as HTMLElement;
      if (["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)) return;
      const combo = pending ? `${pending} ${e.key}` : e.key;
      const hit = NAV.flatMap((g) => g.items).find((i) => i.key === combo);
      if (hit) {
        navigate(hit.to);
        pending = "";
      } else pending = e.key === "g" ? "g" : "";
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navigate, setPalette]);
  if (!paletteOpen) return null;
  const go = (to: string) => {
    navigate(to);
    setPalette(false);
  };
  return (
    <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-[2px]" onClick={() => setPalette(false)}>
      <Command
        label="Command palette"
        className="mx-auto mt-[14vh] w-[min(600px,calc(100vw-32px))] overflow-hidden rounded-lg border border-border bg-surface shadow-pop"
        onClick={(e) => e.stopPropagation()}
      >
        <Command.Input autoFocus placeholder="Type a page, node id or command…" className="h-12 w-full border-b border-border bg-transparent px-4 text-sm outline-none" />
        <Command.List className="scroll-thin max-h-[50vh] overflow-y-auto p-2 text-sm">
          <Command.Empty className="px-3 py-6 text-center text-muted">No results</Command.Empty>
          {NAV.map((g) => (
            <Command.Group key={g.group} heading={g.group} className="[&_[cmdk-group-heading]]:label [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5">
              {g.items.map((it) => (
                <Command.Item key={it.to} onSelect={() => go(it.to)} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 data-[selected=true]:bg-accent/10 data-[selected=true]:text-accent">
                  <it.icon className="size-4" /> {it.label}
                  <span className="ml-auto mono text-[10px] text-subtle">{it.key}</span>
                </Command.Item>
              ))}
            </Command.Group>
          ))}
          <Command.Group heading="Actions" className="[&_[cmdk-group-heading]]:label [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5">
            <Command.Item onSelect={() => { toggleTheme(); setPalette(false); }} className="cursor-pointer rounded-md px-2 py-1.5 data-[selected=true]:bg-accent/10">Toggle dark mode</Command.Item>
            <Command.Item onSelect={() => { api.stop(); setPalette(false); }} className="cursor-pointer rounded-md px-2 py-1.5 data-[selected=true]:bg-accent/10">Stop running simulation</Command.Item>
          </Command.Group>
          {topo.data && (
            <Command.Group heading="Nodes" className="[&_[cmdk-group-heading]]:label [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5">
              {topo.data.nodes.map((n) => (
                <Command.Item key={n.node_id} value={`node ${n.node_id} ${n.ip}`} onSelect={() => { selectNode(n.node_id); go("/network"); }}
                  className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 data-[selected=true]:bg-accent/10">
                  <span className="mono text-xs">{n.node_id}</span>
                  <span className="text-xs text-subtle">{n.ip}</span>
                  {n.probability >= 0.8 && <Badge tone="bad" className="ml-auto">p={n.probability.toFixed(2)}</Badge>}
                </Command.Item>
              ))}
            </Command.Group>
          )}
        </Command.List>
      </Command>
    </div>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-full">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="scroll-thin flex-1 overflow-y-auto bg-bg">
          <div className="mx-auto max-w-[1600px] px-4 py-6 sm:px-6">{children}</div>
        </main>
      </div>
      <CommandPalette />
    </div>
  );
}
