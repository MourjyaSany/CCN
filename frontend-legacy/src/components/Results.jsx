/**
 * Results browser: figure gallery, detector comparison and generated reports.
 *
 * Everything here is read-only and comes from artefacts the command-line
 * pipeline actually wrote. When evaluation has not been run yet the API says so
 * explicitly and this view repeats that rather than rendering empty tables that
 * look like a result of zero.
 */

import React, { useEffect, useMemo, useState } from "react";

import { getFigures, getReport, getReports, getResults } from "../api.js";

const fmt = (v, d = 4) =>
  v === null || v === undefined || Number.isNaN(v) ? "—" : Number(v).toFixed(d);

/** Group figures by the experiment their filename identifies. */
function groupFigures(figures) {
  const groups = new Map();
  for (const figure of figures) {
    const key = figure.experiment || "summary";
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(figure);
  }
  return [...groups.entries()].sort(([a], [b]) =>
    a === "summary" ? -1 : b === "summary" ? 1 : a.localeCompare(b, undefined, { numeric: true }),
  );
}

export default function Results() {
  const [results, setResults] = useState(null);
  const [figures, setFigures] = useState([]);
  const [reports, setReports] = useState([]);
  const [openReport, setOpenReport] = useState(null);
  const [lightbox, setLightbox] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    getResults().then(setResults).catch((e) => setError(e.message));
    getFigures().then(setFigures).catch(() => {});
    getReports().then(setReports).catch(() => {});
  }, []);

  const grouped = useMemo(() => groupFigures(figures), [figures]);

  const showReport = (name) => {
    getReport(name)
      .then(setOpenReport)
      .catch((e) => setError(e.message));
  };

  if (error) return <div className="error">{error}</div>;

  return (
    <div className="results">
      {results && !results.available && (
        <div className="notice">
          {results.message ||
            "No evaluation artefacts yet — run scripts/evaluate.py to generate them."}
        </div>
      )}

      {/* ---- detector comparison ------------------------------------------ */}
      {results?.detectors?.length > 0 && (
        <section className="panel">
          <h2>
            Detector comparison <span className="hint">held-out test split</span>
          </h2>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>Detector</th>
                  <th className="num">Accuracy</th>
                  <th className="num">Macro-F1</th>
                  <th className="num">Attack recall</th>
                  <th className="num">Attack precision</th>
                  <th className="num">FPR</th>
                  <th className="num">ROC-AUC</th>
                </tr>
              </thead>
              <tbody>
                {results.detectors.map((d) => (
                  <tr key={d.detector || d.name}>
                    <td className="mono">{d.detector || d.name}</td>
                    <td className="num">{fmt(d.accuracy)}</td>
                    <td className="num">{fmt(d.macro_f1)}</td>
                    <td className="num">{fmt(d.attack_recall)}</td>
                    <td className="num">{fmt(d.attack_precision)}</td>
                    <td className="num">{fmt(d.fpr, 5)}</td>
                    <td className="num">{fmt(d.roc_auc)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* ---- per-experiment ----------------------------------------------- */}
      {results?.per_experiment?.length > 0 && (
        <section className="panel">
          <h2>
            Per-scenario results <span className="hint">where each detector wins</span>
          </h2>
          <div className="scroll tall">
            <table>
              <thead>
                <tr>
                  <th>Experiment</th>
                  <th>Detector</th>
                  <th className="num">Samples</th>
                  <th className="num">Macro-F1</th>
                  <th className="num">Attack recall</th>
                  <th className="num">FPR</th>
                </tr>
              </thead>
              <tbody>
                {results.per_experiment.map((row, i) => (
                  <tr key={i}>
                    <td className="mono">{row.experiment}</td>
                    <td className="mono">{row.detector}</td>
                    <td className="num">{row.samples ?? "—"}</td>
                    <td className="num">{fmt(row.macro_f1)}</td>
                    <td className="num">{fmt(row.attack_recall)}</td>
                    <td className="num">{fmt(row.fpr, 5)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* ---- reports ------------------------------------------------------- */}
      {reports.length > 0 && (
        <section className="panel">
          <h2>
            Generated reports <span className="hint">{reports.length} files</span>
          </h2>
          <div className="chips">
            {reports.map((r) => (
              <button key={r.name} className="chip" onClick={() => showReport(r.name)}>
                {r.name}
              </button>
            ))}
          </div>
          {openReport && (
            <div className="report-view">
              <div className="report-head">
                <strong>{openReport.name}</strong>
                <button className="ghost" onClick={() => setOpenReport(null)}>
                  Close
                </button>
              </div>
              <pre className="report-body">{openReport.markdown}</pre>
            </div>
          )}
        </section>
      )}

      {/* ---- figures ------------------------------------------------------- */}
      <section className="panel">
        <h2>
          Figures <span className="hint">{figures.length} generated</span>
        </h2>
        {figures.length === 0 ? (
          <p className="muted">
            No figures yet. Run <code>./run.sh evaluate</code> to generate them.
          </p>
        ) : (
          grouped.map(([group, items]) => (
            <div key={group} className="figure-group">
              <h3>{group}</h3>
              <div className="gallery">
                {items.map((f) => (
                  <figure key={f.name} onClick={() => setLightbox(f)}>
                    <img src={f.url} alt={f.name} loading="lazy" />
                    <figcaption>{f.name.replace(/\.png$/, "")}</figcaption>
                  </figure>
                ))}
              </div>
            </div>
          ))
        )}
      </section>

      {lightbox && (
        <div className="lightbox" onClick={() => setLightbox(null)}>
          <img src={lightbox.url} alt={lightbox.name} />
          <div className="lightbox-caption">{lightbox.name}</div>
        </div>
      )}
    </div>
  );
}
