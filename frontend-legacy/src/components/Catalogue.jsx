/**
 * Catalogue views: topology families, attack families, trained models, run
 * history and the environment probe.
 *
 * These are the "what can this system do, and what has it done" pages. They are
 * deliberately plain: each one renders exactly what the corresponding endpoint
 * reports, including the awkward parts (a model that is on disk but not loaded,
 * an NS-3 probe that failed), because hiding those is what makes a dashboard
 * misleading.
 */

import React, { useEffect, useState } from "react";

import {
  getAttacks,
  getEnvironment,
  getModels,
  getRuns,
  getScenarios,
  getTopologies,
} from "../api.js";

/** Colour token per attack layer, matching the project palette. */
const LAYER_TONE = {
  volumetric: "var(--series-2)",
  protocol: "var(--violet)",
  application: "var(--series-1)",
  mixed: "var(--warning)",
};

export function Topologies() {
  const [families, setFamilies] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    getTopologies().then(setFamilies).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="error">{error}</div>;

  return (
    <section className="panel">
      <h2>
        Topology families{" "}
        <span className="hint">
          each changes one structural assumption of the baseline tree
        </span>
      </h2>
      <div className="cards">
        {families.map((f) => (
          <article key={f.name} className="card">
            <h3 className="mono">{f.name}</h3>
            <p>{f.description}</p>
            {Object.keys(f.parameters || {}).length > 0 && (
              <table className="mini">
                <tbody>
                  {Object.entries(f.parameters).map(([k, v]) => (
                    <tr key={k}>
                      <td className="mono">{k}</td>
                      <td className="num">{String(v)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </article>
        ))}
      </div>
      <p className="footnote">
        Every family is validated on construction: one cloud, at least one gateway,
        routers at tier 2, endpoints at tier 3, a non-empty set of enforcement points
        and a reachable route from every endpoint to the cloud.
      </p>
    </section>
  );
}

export function Attacks() {
  const [families, setFamilies] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    getAttacks().then(setFamilies).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="error">{error}</div>;

  return (
    <section className="panel">
      <h2>
        Attack families <span className="hint">by the resource they exhaust</span>
      </h2>
      <div className="cards">
        {families.map((f) => (
          <article key={f.name} className="card">
            <h3 className="mono">
              <i className="swatch" style={{ background: LAYER_TONE[f.layer] }} />
              {f.name}
            </h3>
            <span className="tag">{f.layer}</span>
            <p>{f.description}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

export function Experiments({ onRun, running }) {
  const [scenarios, setScenarios] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    getScenarios().then(setScenarios).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="error">{error}</div>;

  return (
    <section className="panel">
      <h2>
        Experiments <span className="hint">{scenarios.length} declared scenarios</span>
      </h2>
      <div className="scroll tall">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Tags</th>
              <th className="num">Devices</th>
              <th className="num">Bots</th>
              <th className="num">Duration</th>
              <th>Attack</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {scenarios.map((s) => (
              <tr key={s.name}>
                <td>
                  <div className="mono">{s.name}</div>
                  <div className="muted small">{s.description}</div>
                </td>
                <td>
                  {(s.tags || []).map((t) => (
                    <span key={t} className="tag small">{t}</span>
                  ))}
                  {s.holdout && <span className="tag small alert">held out</span>}
                </td>
                <td className="num">{s.n_iot_devices}</td>
                <td className="num">{s.n_attackers}</td>
                <td className="num">{s.duration_s}s</td>
                <td className="mono">{s.attack_type || "benign"}</td>
                <td>
                  <button
                    className="ghost"
                    disabled={running}
                    onClick={() => onRun(s.name)}
                  >
                    Run
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export function Models() {
  const [models, setModels] = useState([]);
  const [environment, setEnvironment] = useState(null);

  useEffect(() => {
    getModels().then(setModels).catch(() => {});
    getEnvironment().then(setEnvironment).catch(() => {});
  }, []);

  return (
    <>
      <section className="panel">
        <h2>
          Trained detectors <span className="hint">manifests on disk</span>
        </h2>
        {models.length === 0 ? (
          <p className="muted">
            No trained models found. Run <code>./run.sh train</code>.
          </p>
        ) : (
          <div className="cards">
            {models.map((m) => (
              <article key={m.detector} className="card">
                <h3 className="mono">{m.display_name || m.detector}</h3>
                <span className={`tag ${m.loaded ? "ok" : "warn"}`}>
                  {m.loaded ? "loaded" : "on disk, not loaded"}
                </span>
                <table className="mini">
                  <tbody>
                    <tr><td>Kind</td><td className="mono">{m.kind}</td></tr>
                    <tr><td>Uses graph</td><td>{m.uses_graph ? "yes" : "no"}</td></tr>
                    <tr><td>Trainable</td><td>{m.trainable ? "yes" : "no"}</td></tr>
                    {m.backend && (
                      <tr><td>Backend</td><td className="mono">{m.backend}</td></tr>
                    )}
                    <tr>
                      <td>Features</td>
                      <td className="num">{(m.feature_columns || []).length}</td>
                    </tr>
                  </tbody>
                </table>
              </article>
            ))}
          </div>
        )}
      </section>

      {environment && (
        <section className="panel">
          <h2>
            Environment <span className="hint">probed, not assumed</span>
          </h2>
          <div className="two-col">
            <div>
              <h3>Simulation engine</h3>
              <table className="mini">
                <tbody>
                  <tr>
                    <td>NS-3 available</td>
                    <td>
                      <span className={`tag ${environment.ns3?.available ? "ok" : "warn"}`}>
                        {String(environment.ns3?.available)}
                      </span>
                    </td>
                  </tr>
                  <tr><td>Method</td><td className="mono">{environment.ns3?.method || "—"}</td></tr>
                  <tr><td>Version</td><td className="mono">{environment.ns3?.version || "—"}</td></tr>
                  {environment.ns3?.distro && (
                    <tr><td>WSL distro</td><td className="mono">{environment.ns3.distro}</td></tr>
                  )}
                  <tr><td>Path</td><td className="mono small">{environment.ns3?.ns3_dir || "—"}</td></tr>
                </tbody>
              </table>
              <p className="muted small">{environment.ns3?.detail}</p>
            </div>
            <div>
              <h3>Libraries</h3>
              <table className="mini">
                <tbody>
                  {Object.entries(environment.libraries || {}).map(([k, v]) => (
                    <tr key={k}>
                      <td className="mono">{k}</td>
                      <td className="mono num">{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}
    </>
  );
}

export function Runs() {
  const [runs, setRuns] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    getRuns().then(setRuns).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="error">{error}</div>;

  return (
    <section className="panel">
      <h2>
        Run history <span className="hint">{runs.length} persisted runs</span>
      </h2>
      {runs.length === 0 ? (
        <p className="muted">No runs persisted yet.</p>
      ) : (
        <div className="scroll tall">
          <table>
            <thead>
              <tr>
                <th>Run id</th>
                <th>Experiment</th>
                <th>Engine</th>
                <th className="num">Duration</th>
                <th className="num">Packets</th>
                <th className="num">Loss</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((r, i) => (
                <tr key={r.run_id || i}>
                  <td className="mono small">{r.run_id}</td>
                  <td className="mono">{r.experiment}</td>
                  <td className="small">{r.engine_label || r.engine}</td>
                  <td className="num">{r.duration_s ?? "—"}</td>
                  <td className="num">
                    {(r.packets_generated ?? 0).toLocaleString?.() ?? "—"}
                  </td>
                  <td className="num">
                    {r.loss_ratio !== undefined && r.loss_ratio !== null
                      ? `${(r.loss_ratio * 100).toFixed(2)}%`
                      : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
