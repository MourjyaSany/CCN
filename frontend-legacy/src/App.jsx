/**
 * NetShield-GNN React console.
 *
 * A tabbed shell over the REST API: the live console, an attack builder that
 * composes a custom campaign, the experiment matrix, the topology and attack
 * catalogues, the results browser and the run history.
 *
 * Polling is centralised here and only runs while the Console tab is visible,
 * so browsing results does not keep hammering the live endpoints.
 */

import React, { useCallback, useEffect, useState } from "react";

import AttackBuilder from "./components/AttackBuilder.jsx";
import Console from "./components/Console.jsx";
import Results from "./components/Results.jsx";
import {
  Attacks,
  Experiments,
  Models,
  Runs,
  Topologies,
} from "./components/Catalogue.jsx";
import { getHealth, getScenarios, pollAll, startSimulation, stopSimulation } from "./api.js";

const POLL_MS = 1500;

const TABS = [
  { id: "console", label: "Live console" },
  { id: "builder", label: "Attack builder" },
  { id: "experiments", label: "Experiments" },
  { id: "topologies", label: "Topologies" },
  { id: "attacks", label: "Attack families" },
  { id: "results", label: "Results" },
  { id: "models", label: "Models" },
  { id: "runs", label: "Run history" },
];

export default function App() {
  const [tab, setTab] = useState("console");
  const [health, setHealth] = useState(null);
  const [scenarios, setScenarios] = useState([]);
  const [snapshot, setSnapshot] = useState({});
  const [scenario, setScenario] = useState("exp8_mitigation");
  const [detector, setDetector] = useState("graphsage");
  const [speed, setSpeed] = useState(5);
  const [mitigation, setMitigation] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    getHealth()
      .then((h) => {
        setHealth(h);
        if (h.detectors_loaded?.length) setDetector(h.detectors_loaded[0]);
        if (h.detectors_loaded?.includes("graphsage")) setDetector("graphsage");
      })
      .catch(() => setError("API unreachable — is the server running?"));
    getScenarios().then(setScenarios).catch(() => {});
  }, []);

  const refresh = useCallback(() => {
    pollAll()
      .then(setSnapshot)
      .catch(() => {
        /* transient during startup; the next tick retries */
      });
  }, []);

  const status = snapshot.status || {};
  const running = status.state === "running" || status.state === "stopping";

  // Poll while the console is open, and also while a run is in flight so the
  // header badge stays truthful on other tabs.
  useEffect(() => {
    refresh();
    if (tab !== "console" && !running) return undefined;
    const timer = setInterval(refresh, POLL_MS);
    return () => clearInterval(timer);
  }, [refresh, tab, running]);

  const launch = async (body) => {
    setError("");
    try {
      await startSimulation(body);
      setTab("console");
      refresh();
    } catch (e) {
      setError(e.message);
    }
  };

  const onStart = () =>
    launch({
      scenario,
      speed: Number(speed) || 0,
      mitigation,
      detector,
    });

  const onStop = async () => {
    try {
      await stopSimulation();
      refresh();
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div className="wrap">
      <header className="top">
        <div className="brand">
          <h1>NetShield-GNN</h1>
          <span className="sub">
            IoT–Cloud DDoS Detection &amp; Automated Mitigation
          </span>
        </div>
        <div className="spacer" />
        <span className="pill" title={`NS-3 available: ${health?.ns3_available}`}>
          <i className="dot" />
          {health?.engine || "checking…"}
        </span>
        <span className={`pill ${running ? "live" : ""}`}>
          <i className="dot" />
          {status.state || "idle"}
          {status.scenario ? ` · ${status.scenario}` : ""}
        </span>
        {status.active_attack && (
          <span className="pill attack">
            <i className="dot" />
            {status.attack_type} in progress
          </span>
        )}
      </header>

      <nav className="tabs">
        {TABS.map((t) => (
          <button
            key={t.id}
            className={`tab ${tab === t.id ? "active" : ""}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      {tab === "console" && (
        <Console
          snapshot={snapshot}
          scenarios={scenarios}
          health={health}
          scenario={scenario}
          setScenario={setScenario}
          detector={detector}
          setDetector={setDetector}
          speed={speed}
          setSpeed={setSpeed}
          mitigation={mitigation}
          setMitigation={setMitigation}
          onStart={onStart}
          onStop={onStop}
          running={running}
          error={error}
        />
      )}

      {tab === "builder" && (
        <AttackBuilder scenarios={scenarios} onLaunch={launch} running={running} />
      )}

      {tab === "experiments" && (
        <Experiments
          running={running}
          onRun={(name) => {
            setScenario(name);
            launch({ scenario: name, speed: Number(speed) || 0, mitigation, detector });
          }}
        />
      )}

      {tab === "topologies" && <Topologies />}
      {tab === "attacks" && <Attacks />}
      {tab === "results" && <Results />}
      {tab === "models" && <Models />}
      {tab === "runs" && <Runs />}

      <footer>
        All attack traffic is generated inside an in-memory discrete-event
        simulator. No packet produced by this system leaves the host.
        <br />
        <a href="/docs">OpenAPI documentation</a> ·{" "}
        <a href="/">Bundled dashboard</a>
      </footer>
    </div>
  );
}
