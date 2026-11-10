import { useEffect, useRef, useState } from "react";
import { Pause, Play, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui";

/**
 * A self-contained, data-labelled visualisation of what the gateway policer
 * does to a DDoS flood, built because NetAnim draws every packet identically
 * and so cannot show a packet's *fate*. Here attack packets are red and legit
 * packets are green, and the three phases are unmistakable:
 *   - FLOOD     : red packets stream straight through to the cloud
 *   - SLOWED    : most red packets are dropped at the gateway (✕); a trickle passes
 *   - BLOCKED   : every red packet is stopped dead at the gateway
 * Legit (green) traffic flows the whole time, showing the fleet stays up.
 *
 * The phase timeline mirrors the real policer (watch → rate-limit → block);
 * the headline figure shown is the measured ``blockedPct`` from the NS-3 run.
 */

type Phase = "flood" | "slowed" | "blocked";

interface Packet {
  x: number; y: number; sx: number; sy: number; seg: 0 | 1; t: number;
  kind: "atk" | "legit"; dropped: boolean; fade: number;
}

const W = 760;
const H = 430;
const GW = { x: 400, y: 222 };       // gateway centre
const CLOUD = { x: 430, y: 70 };     // cloud centre
const LOOP = 18;                      // seconds per cycle
const PHASES: Array<{ p: Phase; from: number; to: number; label: string; color: string }> = [
  { p: "flood", from: 0, to: 4.5, label: "DDoS flood — no defence", color: "#ef4444" },
  { p: "slowed", from: 4.5, to: 9, label: "Rate-limited — flood throttled", color: "#f59e0b" },
  { p: "blocked", from: 9, to: 18, label: "Blocked — flood cut off", color: "#111827" },
];

function phaseAt(t: number): typeof PHASES[number] {
  return PHASES.find((ph) => t >= ph.from && t < ph.to) ?? PHASES[PHASES.length - 1];
}

export function MitigationTheatre({ blockedPct, topology, attackType }: {
  blockedPct?: number | null; topology?: string; attackType?: string;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [playing, setPlaying] = useState(true);
  const [phaseLabel, setPhaseLabel] = useState(PHASES[0].label);
  const stateRef = useRef({ t: 0, packets: [] as Packet[], reached: 0, stopped: 0, legit: 0, acc: 0, lacc: 0 });
  const playingRef = useRef(true);
  playingRef.current = playing;

  // node layout (built once)
  const attackers = Array.from({ length: 4 }, (_, i) => ({ x: 70 + i * 72, y: 372 }));
  const iot = Array.from({ length: 3 }, (_, i) => ({ x: 486 + i * 82, y: 372 }));

  const reset = () => {
    const s = stateRef.current;
    s.t = 0; s.packets = []; s.reached = 0; s.stopped = 0; s.legit = 0; s.acc = 0; s.lacc = 0;
  };

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    canvas.width = W * dpr; canvas.height = H * dpr;
    ctx.scale(dpr, dpr);

    let raf = 0;
    let prev = performance.now();
    const css = (v: string) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
    const tok = (name: string, a = 1) => { const c = css(`--${name}`); return `rgba(${c.split(" ").join(",")}, ${a})`; };

    const drawNode = (x: number, y: number, r: number, fill: string, label?: string, stroke?: string) => {
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
      ctx.fillStyle = fill; ctx.fill();
      if (stroke) { ctx.lineWidth = 2; ctx.strokeStyle = stroke; ctx.stroke(); }
      if (label) { ctx.fillStyle = tok("muted"); ctx.font = "600 10px ui-sans-serif, system-ui"; ctx.textAlign = "center"; ctx.fillText(label, x, y + r + 12); }
    };

    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - prev) / 1000);
      prev = now;
      const s = stateRef.current;
      if (playingRef.current) {
        s.t = (s.t + dt) % LOOP;
        if (s.t < dt) { s.reached = 0; s.stopped = 0; s.legit = 0; } // new cycle
      }
      const ph = phaseAt(s.t);

      // ---- spawn ----
      if (playingRef.current) {
        // attackers emit fast throughout (the botnet does not cooperate)
        s.acc += dt;
        const atkEvery = 1 / 26; // ~26 attack packets/s total
        while (s.acc >= atkEvery) {
          s.acc -= atkEvery;
          const a = attackers[Math.floor(Math.random() * attackers.length)];
          s.packets.push({ x: a.x, y: a.y, sx: a.x, sy: a.y, seg: 0, t: 0, kind: "atk", dropped: false, fade: 1 });
        }
        // legit devices emit a steady trickle the whole time
        s.lacc += dt;
        const legitEvery = 1 / 7;
        while (s.lacc >= legitEvery) {
          s.lacc -= legitEvery;
          const a = iot[Math.floor(Math.random() * iot.length)];
          s.packets.push({ x: a.x, y: a.y, sx: a.x, sy: a.y, seg: 0, t: 0, kind: "legit", dropped: false, fade: 1 });
        }
      }

      // ---- advance ----
      const speed = 1.7;
      for (const p of s.packets) {
        if (p.dropped) { p.fade -= dt * 2.5; continue; }
        p.t += dt * speed;
        const tgt = p.seg === 0 ? GW : CLOUD;
        const ox = p.seg === 0 ? p.sx : GW.x, oy = p.seg === 0 ? p.sy : GW.y;
        p.x = ox + (tgt.x - ox) * Math.min(1, p.t);
        p.y = oy + (tgt.y - oy) * Math.min(1, p.t);
        if (p.t >= 1) {
          if (p.seg === 0) {
            // reached the gateway — decide fate
            if (p.kind === "atk") {
              const dropProb = ph.p === "flood" ? 0 : ph.p === "slowed" ? 0.82 : 1;
              if (Math.random() < dropProb) { p.dropped = true; s.stopped++; continue; }
            }
            p.seg = 1; p.t = 0;
          } else {
            // reached the cloud
            if (p.kind === "atk") s.reached++; else s.legit++;
            p.fade = 0; // mark for removal
          }
        }
      }
      s.packets = s.packets.filter((p) => p.fade > 0.02 || (!p.dropped && p.t < 1.2));
      s.packets = s.packets.filter((p) => !(p.seg === 1 && p.t >= 1));

      // ---- draw ----
      ctx.clearRect(0, 0, W, H);
      // links
      ctx.strokeStyle = tok("border", 0.9); ctx.lineWidth = 1.5;
      for (const a of [...attackers, ...iot]) { ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(GW.x, GW.y); ctx.stroke(); }
      ctx.beginPath(); ctx.moveTo(GW.x, GW.y); ctx.lineTo(CLOUD.x, CLOUD.y); ctx.lineWidth = 2.5; ctx.stroke();

      // packets
      for (const p of s.packets) {
        ctx.globalAlpha = p.dropped ? Math.max(0, p.fade) : 1;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.kind === "atk" ? 3.4 : 3, 0, Math.PI * 2);
        ctx.fillStyle = p.kind === "atk" ? "#ef4444" : "#22c55e"; ctx.fill();
        if (p.dropped) { // a small red ✕ where it was stopped
          ctx.strokeStyle = "#ef4444"; ctx.lineWidth = 1.6; const d = 4;
          ctx.beginPath(); ctx.moveTo(p.x - d, p.y - d); ctx.lineTo(p.x + d, p.y + d);
          ctx.moveTo(p.x + d, p.y - d); ctx.lineTo(p.x - d, p.y + d); ctx.stroke();
        }
      }
      ctx.globalAlpha = 1;

      // nodes
      drawNode(CLOUD.x, CLOUD.y, 22, "#2563eb", "CLOUD (target)", "#60a5fa");
      const gwActive = ph.p !== "flood";
      drawNode(GW.x, GW.y, 18, gwActive ? "#334155" : "#64748b", "GATEWAY · policer", gwActive ? ph.color : undefined);
      const atkFill = ph.p === "flood" ? "#ef4444" : ph.p === "slowed" ? "#f59e0b" : "#111827";
      attackers.forEach((a, i) => drawNode(a.x, a.y, ph.p === "blocked" ? 9 : 13, atkFill, i === 0 ? "attackers (botnet)" : undefined, ph.p === "blocked" ? "#334155" : undefined));
      iot.forEach((a, i) => drawNode(a.x, a.y, 12, "#22c55e", i === 0 ? "IoT devices (legit)" : undefined));

      // phase banner
      ctx.fillStyle = ph.color; ctx.globalAlpha = ph.p === "blocked" ? 1 : 0.9;
      ctx.font = "700 15px ui-sans-serif, system-ui"; ctx.textAlign = "left";
      ctx.fillText(ph.label, 16, 26); ctx.globalAlpha = 1;
      // progress bar
      ctx.fillStyle = tok("border"); ctx.fillRect(16, 34, W - 32, 4);
      ctx.fillStyle = ph.color; ctx.fillRect(16, 34, (W - 32) * (s.t / LOOP), 4);

      // live counters (right)
      ctx.textAlign = "right"; ctx.font = "600 12px ui-sans-serif, system-ui";
      ctx.fillStyle = "#22c55e"; ctx.fillText(`legit delivered: ${s.legit}`, W - 16, 20);
      ctx.fillStyle = "#ef4444"; ctx.fillText(`attack reached cloud: ${s.reached}`, W - 16, 38);
      ctx.fillStyle = tok("muted"); ctx.fillText(`stopped at gateway: ${s.stopped}`, W - 16, 56);

      if (ph.label !== phaseLabel) setPhaseLabel(ph.label);
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div className="text-sm font-semibold text-fg">
          Mitigation theatre
          {blockedPct != null && <span className="ml-2 rounded-full bg-good/15 px-2 py-0.5 text-xs font-semibold text-good">{(blockedPct * 100).toFixed(1)}% of attack blocked</span>}
        </div>
        <div className="flex items-center gap-1.5">
          <Button size="xs" variant="secondary" onClick={() => setPlaying((p) => !p)}>{playing ? <><Pause /> Pause</> : <><Play /> Play</>}</Button>
          <Button size="xs" variant="ghost" onClick={reset}><RotateCcw /> Restart</Button>
        </div>
      </div>
      <canvas ref={canvasRef} className="w-full rounded-lg border border-border bg-raised" style={{ aspectRatio: `${W} / ${H}` }} />
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted">
        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full" style={{ background: "#ef4444" }} /> attack packet</span>
        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full" style={{ background: "#22c55e" }} /> legit packet</span>
        <span className="flex items-center gap-1"><span style={{ color: "#ef4444" }}>✕</span> stopped at gateway</span>
        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full" style={{ background: "#f59e0b" }} /> rate-limited node</span>
        <span className="flex items-center gap-1"><span className="size-2.5 rounded-full bg-black ring-1 ring-border" /> blocked node</span>
        {(topology || attackType) && <span className="ml-auto">{topology} · {attackType}</span>}
      </div>
    </div>
  );
}
