# NetShield-GNN — Troubleshooting

Start here:

```bash
python scripts/check_env.py
```

That script **imports every library and executes every tool it reports on** — it
never guesses — and writes a machine-readable record to
`results/reports/environment.json`. Exit status 0 means every *required*
dependency is present. Optional components are reported but never fail the
check, because each has a documented fallback.

---

## 1. "NS-3 not available"

```
[warn] NS-3 not available on this host.
       No usable NS-3 installation found...
[warn] Results will be labelled: Python discrete-event emulation
```

**This is not an error.** It is the expected message on a machine without a C++
toolchain, and the project is fully functional in this configuration — it is how
every result currently in the repository was produced.

What happens instead: the built-in discrete-event engine runs, and every
artefact is stamped `"Python discrete-event emulation"` in `run.json`, in the
`engine` column of `dataset.csv`, in the caption of every figure and in the
header of `RESULTS.md`.

**If you want NS-3:**

```bash
export NS3_DIR=$HOME/ns-3-dev
bash ns3/scripts/build_ns3.sh --run
python scripts/check_env.py        # should now report "NS-3 detected"
```

Then set `simulation.engine: ns3` in `config/default.yaml`. In that mode a
missing installation is a hard error (`NS3Unavailable`), never a silent
fallback — see [`ns3/README.md`](../ns3/README.md).

---

## 2. "torch_geometric missing"

```
[warn] torch_geometric  missing - GraphSAGE falls back to the pure-PyTorch
       MeanSAGEConv layer
```

The project still runs. `netshield.models.graphsage.MeanSAGEConv` implements
mean-aggregation GraphSAGE directly on `index_add_` and is mathematically
equivalent to `torch_geometric.nn.SAGEConv(aggr="mean")`; a unit test asserts
the equivalence numerically. The active backend is printed in every training log
and recorded in the checkpoint manifest, so results are never ambiguous.

To install it:

```bash
pip install torch-geometric
```

If the wheel fails to build, you are on a platform without a prebuilt wheel.
Use the fallback — it is a supported configuration, not a degraded one.

---

## 3. "No trained detectors found"

```
No trained detectors found under .../models. Run 'python scripts/train_models.py' first.
```

The pipeline has an order:

```bash
python scripts/generate_dataset.py   # 1. simulate and featurise
python scripts/train_models.py       # 2. train
python scripts/evaluate.py           # 3. evaluate
```

`scripts/run_experiment.py` degrades gracefully — it warns and continues in
simulate-only mode, producing network figures without detection.

---

## 4. "Dataset not found"

```
Dataset not found: .../data/processed/dataset.csv.
Run 'python scripts/generate_dataset.py' first.
```

Generate it. For a fast smoke run:

```bash
python scripts/generate_dataset.py --quick     # ~2 min instead of ~6
```

---

## 5. Dataset generation is slow

Expected: roughly six minutes for the full 28-run corpus.

- `--reuse` skips runs whose artefacts already exist. Run ids are a hash of the
  exact configuration, so a reused run is byte-identical to a fresh one — this
  is safe, not an approximation.
- `--quick` uses fewer seeds, fewer fuzz cases and shorter runs.
- `--duration 50` shortens every run.
- `--no-fuzz` skips the fuzzing portion.

```bash
python scripts/generate_dataset.py --reuse --duration 60
```

---

## 6. "Wall-clock budget of 240s exhausted"

```
WARNING  Wall-clock budget of 240s exhausted at simulated t=42.0s of 70.0s;
         stopping early and marking the run truncated.
```

A safety rail, working as designed. The fuzzer can legitimately choose an attack
rate that would take hours to simulate (an HTTP flood at 3000 requests/second
from 10 bots expands to ~240,000 packets/second, because each request is a full
TCP transaction). Rather than hanging a batch job, the run stops, is marked
`wall_budget_hit: true` with a `completed_fraction`, and the caller reports it
honestly.

To raise the budget:

```bash
python scripts/generate_dataset.py --set simulation.max_wall_seconds=900
```

---

## 7. Out of memory during dataset generation

A SYN flood with source spoofing produces a very large flow table — over 100,000
flow records in one run — because each spoofed address times a source port is a
distinct 5-tuple. That is realistic (flow-table explosion is a genuine DDoS
symptom) but memory-hungry.

Mitigations:

```bash
python scripts/generate_dataset.py --duration 50          # fewer windows
python scripts/generate_dataset.py --set attack.spoof_pool=32
python scripts/generate_dataset.py --set simulation.max_packets=1000000
```

The database persists only the top 20,000 flow rows per run by packet count;
the full table stays in `data/experiments/<run_id>/flows.csv`.

---

## 8. The dashboard shows no data

The dashboard visualises a **live** simulation. On a fresh start everything is
empty until you press **Start simulation**.

- No scenarios in the dropdown → the API cannot read `config/experiments.yaml`;
  check the server log.
- Detector dropdown says `(none trained)` → run `scripts/train_models.py`.
- The **View results** panel says results are unavailable → run
  `scripts/evaluate.py`.
- Topology stays empty while running → check the server log for a controller
  exception; failures set `state: failed` and populate `error` on
  `/api/simulation/status`.

---

## 9. "Address already in use"

```bash
NETSHIELD_PORT=8080 ./run.sh dashboard
# or
python scripts/serve.py --port 8080
```

---

## 10. `./run.sh` will not execute

On Windows, use Git Bash or WSL, or call the scripts directly — every `run.sh`
target is a thin wrapper:

```powershell
python scripts\check_env.py
python scripts\generate_dataset.py
python scripts\train_models.py
python scripts\run_experiment.py --all
python scripts\evaluate.py
python scripts\serve.py
python scripts\demo.py
```

On Linux/macOS, if you get "permission denied":

```bash
chmod +x run.sh
```

To use a specific interpreter:

```bash
PYTHON=/usr/bin/python3.12 ./run.sh setup
```

---

## 11. Import errors when running a script directly

Every script inserts `src/` onto `sys.path` via `scripts/_bootstrap.py`, so no
installation is needed — but only if you run them as files from the repository:

```bash
python scripts/train_models.py        # correct
python -m scripts.train_models        # will not resolve the bootstrap
```

For use as a library:

```bash
pip install -e .
```

---

## 12. Tests fail

```bash
pytest -v                              # see which
pytest tests/test_simulation.py -v     # one suite
```

The tests run **real simulations** rather than mocks, so a failure in
`TestVolumetricAttack` usually means the simulation genuinely did not congest.
Check the fixture arithmetic in `tests/conftest.py`: the attack rate is chosen
from the link budget, and a rate that merely approaches capacity leaves the
congestion assertions testing nothing.

If `TestAPI` is skipped, install the test transport:

```bash
pip install httpx
```

---

## 13. Figures are not generated

Matplotlib must use a headless backend. `evaluation/figures.py` sets
`matplotlib.use("Agg")` before importing `pyplot`, so this should be automatic.
If you have a stale `MPLBACKEND` in the environment:

```bash
MPLBACKEND=Agg python scripts/evaluate.py
```

Figure generation is wrapped so a rendering failure warns and continues rather
than aborting the whole evaluation — check the log for a `figure generation
failed` warning.

---

## 14. Results differ between runs

They should not. Everything is seeded from `seed` in `config/default.yaml` plus
the per-experiment overrides, and `TestReproducibility` asserts that two runs of
the same configuration produce identical flow tables.

If you see drift, check that you have not changed a configuration file between
runs — the run id embeds a hash of the full configuration, so a changed
`run_id` means a changed configuration.

---

## 15. Docker issues

```bash
docker compose build --no-cache        # rebuild from scratch
docker compose run --rm netshield python scripts/check_env.py
docker compose logs -f
```

The image installs the CPU wheel of PyTorch deliberately: the models are small
and the simulator is single-threaded Python, so a GPU buys nothing and a CPU
image runs anywhere.

Artefact directories are bind-mounted, so results appear on the host under
`data/`, `models/` and `results/`.

---

## 16. Getting more detail

```bash
python scripts/run_experiment.py --experiment exp2_udp_flood --log-level DEBUG
```

Every script writes a full log to `results/logs/<script>.log` regardless of the
console level.

---

## Still stuck?

Collect these three things before asking:

```bash
python scripts/check_env.py > env.txt 2>&1
cat results/reports/environment.json
tail -50 results/logs/<the-failing-script>.log
```

Together they identify the interpreter, every library version, which optional
components are present, and exactly where the failure occurred.
