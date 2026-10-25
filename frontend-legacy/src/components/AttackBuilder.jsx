/**
 * Attack Builder: compose a custom attack + topology and launch it.
 *
 * Every control here maps to one dotted configuration key. The form is driven
 * by `/api/attacks/schema`, so a knob added to config/default.yaml appears here
 * without the UI needing to be changed, and the resolved profile is validated
 * server-side through `/api/attack/preview` *before* a simulation is started —
 * so a bad combination reports its exact error instead of failing minutes into
 * a run.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";

import { getAttacks, getAttackSchema, getTopologies, previewAttack } from "../api.js";

/** Families whose rate is expressed as something other than packets/second. */
const RATE_UNITS = {
  http_flood: "requests/s (each expands to a full TCP transaction)",
  slowloris: "new sockets/s (each is then held open)",
};

/** Sensible per-family starting points, used when the family is switched. */
const FAMILY_PRESETS = {
  udp_flood: { packets_per_second: 1400, packet_bytes: [512, 512], dst_ports: [8883, 5683] },
  syn_flood: { packets_per_second: 1800, packet_bytes: [60, 60], dst_ports: [80, 443, 8883] },
  http_flood: { packets_per_second: 320, packet_bytes: [420, 900], dst_ports: [80, 443] },
  icmp_flood: { packets_per_second: 1600, packet_bytes: [64, 512], dst_ports: [0] },
  ack_flood: { packets_per_second: 2000, packet_bytes: [64, 64], dst_ports: [80, 443] },
  slowloris: { packets_per_second: 12, packet_bytes: [64, 128], dst_ports: [80, 443] },
  mixed: { packets_per_second: 900, packet_bytes: [128, 1200], dst_ports: [80, 8883, 5683] },
};

/** Parse "80, 443" into [80, 443]; tolerates empty entries while typing. */
function parsePorts(text) {
  return String(text)
    .split(",")
    .map((p) => parseInt(p.trim(), 10))
    .filter((p) => Number.isFinite(p));
}

function Field({ label, hint, children }) {
  return (
    <label className="builder-field">
      <span className="builder-label">{label}</span>
      {children}
      {hint && <span className="builder-hint">{hint}</span>}
    </label>
  );
}

export default function AttackBuilder({ scenarios, onLaunch, running }) {
  const [schema, setSchema] = useState(null);
  const [families, setFamilies] = useState([]);
  const [topologies, setTopologies] = useState([]);
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // The builder state is a flat mirror of the configuration keys it controls.
  const [form, setForm] = useState({
    base: "exp2_udp_flood",
    family: "tree",
    type: "udp_flood",
    n_iot: 24,
    n_attackers: 4,
    duration_s: 90,
    start_s: 30,
    attack_duration_s: 30,
    pps: 1400,
    bytesLo: 512,
    bytesHi: 512,
    ports: "8883, 5683",
    target: "cloud",
    shape: "constant",
    rampStart: 0.05,
    rampEnd: 1.0,
    sinePeriod: 18,
    sineDepth: 0.6,
    stepInterval: 5,
    jitterLo: 1.0,
    jitterHi: 1.0,
    stagger: 0,
    burst: false,
    burstOn: 2.5,
    burstOff: 3.5,
    spoof: false,
    spoofPool: 64,
    slowlorisSockets: 40,
    slowlorisKeepalive: 6,
    mitigation: true,
    speed: 5,
  });

  useEffect(() => {
    getAttackSchema().then(setSchema).catch((e) => setError(e.message));
    getAttacks().then(setFamilies).catch(() => {});
    getTopologies().then(setTopologies).catch(() => {});
  }, []);

  const set = (key) => (event) => {
    const el = event.target;
    const value =
      el.type === "checkbox"
        ? el.checked
        : el.type === "number"
          ? Number(el.value)
          : el.value;
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  /** Switching family applies that family's preset so the rate stays sane. */
  const onFamilyChange = (event) => {
    const type = event.target.value;
    const preset = FAMILY_PRESETS[type] || {};
    setForm((prev) => ({
      ...prev,
      type,
      pps: preset.packets_per_second ?? prev.pps,
      bytesLo: preset.packet_bytes?.[0] ?? prev.bytesLo,
      bytesHi: preset.packet_bytes?.[1] ?? prev.bytesHi,
      ports: (preset.dst_ports ?? parsePorts(prev.ports)).join(", "),
    }));
  };

  /** Translate the form into the dotted overrides the API accepts. */
  const overrides = useMemo(() => {
    const out = {
      "network.topology.family": form.family,
      "simulation.n_iot_devices": form.n_iot,
      "simulation.n_attackers": form.n_attackers,
      "simulation.duration_s": form.duration_s,
      "attack.enabled": form.n_attackers > 0,
      "attack.type": form.type,
      "attack.start_s": form.start_s,
      "attack.duration_s": form.attack_duration_s,
      "attack.packets_per_second": form.pps,
      "attack.packet_bytes": [form.bytesLo, form.bytesHi],
      "attack.dst_ports": parsePorts(form.ports),
      "attack.target": form.target,
      "attack.shape.profile": form.shape,
      "attack.rate_jitter": [form.jitterLo, form.jitterHi],
      "attack.stagger_s": form.stagger,
      "attack.burst.enabled": form.burst,
      "attack.spoof_sources": form.spoof,
      "mitigation.enabled": form.mitigation,
    };
    if (form.shape === "ramp") {
      out["attack.shape.ramp_start_factor"] = form.rampStart;
      out["attack.shape.ramp_end_factor"] = form.rampEnd;
    }
    if (form.shape === "sine") {
      out["attack.shape.sine_period_s"] = form.sinePeriod;
      out["attack.shape.sine_depth"] = form.sineDepth;
    }
    if (form.shape === "step") {
      out["attack.shape.step_interval_s"] = form.stepInterval;
    }
    if (form.burst) {
      out["attack.burst.on_s"] = form.burstOn;
      out["attack.burst.off_s"] = form.burstOff;
    }
    if (form.spoof) out["attack.spoof_pool"] = form.spoofPool;
    if (form.type === "slowloris") {
      out["attack.slowloris.sockets"] = form.slowlorisSockets;
      out["attack.slowloris.keepalive_s"] = form.slowlorisKeepalive;
    }
    return out;
  }, [form]);

  // Validate server-side whenever the composed configuration changes.
  const validate = useCallback(() => {
    setBusy(true);
    previewAttack({ scenario: form.base, overrides })
      .then((result) => {
        setPreview(result);
        setError("");
      })
      .catch((e) => {
        setPreview(null);
        setError(e.message);
      })
      .finally(() => setBusy(false));
  }, [form.base, overrides]);

  useEffect(() => {
    const timer = setTimeout(validate, 350); // debounce while typing
    return () => clearTimeout(timer);
  }, [validate]);

  const launch = () => {
    onLaunch({
      scenario: form.base,
      speed: Number(form.speed) || 0,
      mitigation: form.mitigation,
      overrides,
    });
  };

  const valid = preview?.valid === true;
  const rateUnit = RATE_UNITS[form.type] || "packets/s per bot";

  return (
    <div className="builder">
      <div className="builder-grid">
        {/* ---- scenario & network ---------------------------------------- */}
        <section className="panel">
          <h2>
            Network <span className="hint">what the attack runs against</span>
          </h2>

          <Field label="Base scenario" hint="Overrides are merged onto this scenario.">
            <select value={form.base} onChange={set("base")}>
              {scenarios.map((s) => (
                <option key={s.name} value={s.name}>{s.name}</option>
              ))}
            </select>
          </Field>

          <Field
            label="Topology family"
            hint={topologies.find((t) => t.name === form.family)?.description}
          >
            <select value={form.family} onChange={set("family")}>
              {topologies.map((t) => (
                <option key={t.name} value={t.name}>{t.name}</option>
              ))}
            </select>
          </Field>

          <div className="builder-row">
            <Field label="IoT devices">
              <input type="number" min="1" max="128" value={form.n_iot}
                     onChange={set("n_iot")} />
            </Field>
            <Field label="Compromised bots">
              <input type="number" min="0" max="64" value={form.n_attackers}
                     onChange={set("n_attackers")} />
            </Field>
          </div>

          <div className="builder-row">
            <Field label="Duration (s)">
              <input type="number" min="10" max="300" value={form.duration_s}
                     onChange={set("duration_s")} />
            </Field>
            <Field label="Playback speed" hint="sim s per real s; 0 = as fast as possible">
              <input type="number" min="0" max="60" value={form.speed}
                     onChange={set("speed")} />
            </Field>
          </div>

          <label className="check">
            <input type="checkbox" checked={form.mitigation} onChange={set("mitigation")} />
            Automated mitigation (closed loop)
          </label>
        </section>

        {/* ---- attack ----------------------------------------------------- */}
        <section className="panel">
          <h2>
            Attack <span className="hint">what the botnet does</span>
          </h2>

          <Field
            label="Family"
            hint={families.find((f) => f.name === form.type)?.description}
          >
            <select value={form.type} onChange={onFamilyChange}>
              {families.map((f) => (
                <option key={f.name} value={f.name}>
                  {f.name} — {f.layer}
                </option>
              ))}
            </select>
          </Field>

          <div className="builder-row">
            <Field label="Starts at (s)">
              <input type="number" min="0" value={form.start_s} onChange={set("start_s")} />
            </Field>
            <Field label="Lasts (s)">
              <input type="number" min="1" value={form.attack_duration_s}
                     onChange={set("attack_duration_s")} />
            </Field>
          </div>

          <Field label="Rate" hint={rateUnit}>
            <input type="number" min="1" max="20000" value={form.pps} onChange={set("pps")} />
          </Field>

          <div className="builder-row">
            <Field label="Payload min (B)">
              <input type="number" min="1" max="1500" value={form.bytesLo}
                     onChange={set("bytesLo")} />
            </Field>
            <Field label="Payload max (B)">
              <input type="number" min="1" max="1500" value={form.bytesHi}
                     onChange={set("bytesHi")} />
            </Field>
          </div>

          <Field label="Destination ports" hint="Comma separated. ICMP ignores ports.">
            <input type="text" value={form.ports} onChange={set("ports")} />
          </Field>

          <Field label="Target" hint="A role, or a node id such as gw-1.">
            <input type="text" value={form.target} onChange={set("target")} />
          </Field>

          {form.type === "slowloris" && (
            <div className="builder-row">
              <Field label="Sockets per bot">
                <input type="number" min="1" max="500" value={form.slowlorisSockets}
                       onChange={set("slowlorisSockets")} />
              </Field>
              <Field label="Keep-alive (s)">
                <input type="number" min="0.5" step="0.5" value={form.slowlorisKeepalive}
                       onChange={set("slowlorisKeepalive")} />
              </Field>
            </div>
          )}
        </section>

        {/* ---- shaping ---------------------------------------------------- */}
        <section className="panel">
          <h2>
            Shaping <span className="hint">how the rate evolves</span>
          </h2>

          <Field
            label="Rate profile"
            hint="A ramp crosses a static threshold late — the interesting evasion case."
          >
            <select value={form.shape} onChange={set("shape")}>
              {(schema?.rate_profiles || ["constant"]).map((p) => (
                <option key={p} value={p}>{p}</option>
              ))}
            </select>
          </Field>

          {form.shape === "ramp" && (
            <div className="builder-row">
              <Field label="Start factor">
                <input type="number" step="0.05" min="0.01" max="1" value={form.rampStart}
                       onChange={set("rampStart")} />
              </Field>
              <Field label="End factor">
                <input type="number" step="0.05" min="0.01" max="2" value={form.rampEnd}
                       onChange={set("rampEnd")} />
              </Field>
            </div>
          )}

          {form.shape === "sine" && (
            <div className="builder-row">
              <Field label="Period (s)">
                <input type="number" min="1" value={form.sinePeriod}
                       onChange={set("sinePeriod")} />
              </Field>
              <Field label="Depth">
                <input type="number" step="0.1" min="0" max="1" value={form.sineDepth}
                       onChange={set("sineDepth")} />
              </Field>
            </div>
          )}

          {form.shape === "step" && (
            <Field label="Step interval (s)">
              <input type="number" min="1" value={form.stepInterval}
                     onChange={set("stepInterval")} />
            </Field>
          )}

          <div className="builder-row">
            <Field label="Rate jitter min" hint="Per-bot multiplier">
              <input type="number" step="0.1" min="0.1" value={form.jitterLo}
                     onChange={set("jitterLo")} />
            </Field>
            <Field label="Rate jitter max">
              <input type="number" step="0.1" min="0.1" value={form.jitterHi}
                     onChange={set("jitterHi")} />
            </Field>
          </div>

          <Field label="Join stagger (s)" hint="Bots activate spread over this window.">
            <input type="number" min="0" value={form.stagger} onChange={set("stagger")} />
          </Field>

          <label className="check">
            <input type="checkbox" checked={form.burst} onChange={set("burst")} />
            Pulsing (on/off duty cycle)
          </label>
          {form.burst && (
            <div className="builder-row">
              <Field label="On (s)">
                <input type="number" step="0.5" min="0.1" value={form.burstOn}
                       onChange={set("burstOn")} />
              </Field>
              <Field label="Off (s)">
                <input type="number" step="0.5" min="0.1" value={form.burstOff}
                       onChange={set("burstOff")} />
              </Field>
            </div>
          )}

          <label className="check">
            <input type="checkbox" checked={form.spoof} onChange={set("spoof")} />
            Spoof source addresses
          </label>
          {form.spoof && (
            <Field label="Spoof pool size"
                   hint="Drawn from 10.66/16, which no simulated device ever uses.">
              <input type="number" min="1" max="1024" value={form.spoofPool}
                     onChange={set("spoofPool")} />
            </Field>
          )}
        </section>
      </div>

      {/* ---- validation + launch ------------------------------------------ */}
      <section className="panel builder-summary">
        <h2>
          Resolved configuration{" "}
          <span className="hint">validated on the server before launch</span>
        </h2>

        {error && <div className="error">{error}</div>}
        {busy && !preview && <p className="muted">Validating…</p>}

        {preview && !preview.valid && (
          <div className="error">Invalid configuration — {preview.error}</div>
        )}

        {valid && (
          <>
            <div className="kpis compact">
              <div className="kpi">
                <div className="kpi-label">Aggregate rate</div>
                <div className="kpi-value">
                  {Math.round(preview.aggregate_pps).toLocaleString()}
                  <span className="kpi-unit">pkt/s</span>
                </div>
                <div className="kpi-foot">{preview.n_attackers} bots</div>
              </div>
              <div className="kpi">
                <div className="kpi-label">Attack packets</div>
                <div className="kpi-value">
                  {preview.estimated_packets.toLocaleString()}
                </div>
                <div className="kpi-foot">estimated over the window</div>
              </div>
              <div className="kpi">
                <div className="kpi-label">Topology</div>
                <div className="kpi-value small">{preview.topology_family}</div>
                <div className="kpi-foot">{preview.n_iot_devices} devices</div>
              </div>
              <div className="kpi">
                <div className="kpi-label">Waveform</div>
                <div className="kpi-value small">{preview.profile.shape.profile}</div>
                <div className="kpi-foot">
                  {preview.profile.burst.enabled ? "pulsing" : "continuous"}
                </div>
              </div>
            </div>

            <details className="overrides">
              <summary>Configuration overrides sent to the API</summary>
              <pre>{JSON.stringify(preview.overrides, null, 2)}</pre>
            </details>
          </>
        )}

        <div className="builder-actions">
          <button className="primary" onClick={launch} disabled={!valid || running}>
            ▶ Launch this attack
          </button>
          {running && <span className="muted">A simulation is already running.</span>}
        </div>

        <p className="footnote">
          The API accepts overrides only under{" "}
          <code>{(schema?.allowed_override_prefixes || []).join(", ")}</code>. There is
          no host, port, interface or real-world target parameter anywhere in this form:
          every packet it produces exists only inside the server's own simulator.
        </p>
      </section>
    </div>
  );
}
