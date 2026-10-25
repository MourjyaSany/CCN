#!/usr/bin/env bash
# =============================================================================
# NetShield-GNN :: single entry point
# -----------------------------------------------------------------------------
#   ./run.sh setup      check dependencies and create the directory layout
#   ./run.sh simulate   run one scenario (default: exp2_udp_flood)
#   ./run.sh dataset    generate the labelled corpus from simulation
#   ./run.sh train      train the threshold, Random Forest and GraphSAGE models
#   ./run.sh experiments run the full Experiment 1-8 suite
#   ./run.sh evaluate   compute metrics, render figures, write RESULTS.md
#   ./run.sh fuzz       run a dynamic fuzzing campaign
#   ./run.sh dashboard  start the API + dashboard on http://127.0.0.1:8000
#   ./run.sh demo       ~2-minute live presentation demonstration
#   ./run.sh test       run the automated test suite
#   ./run.sh frontend   build (or dev-serve) the React dashboard
#   ./run.sh all        setup -> dataset -> train -> experiments -> evaluate
#                       -> dashboard
#   ./run.sh clean      remove generated artefacts
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
export NETSHIELD_ROOT="$ROOT"
export PYTHONUNBUFFERED=1

# --- python interpreter discovery -------------------------------------------
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  if [ -x "$ROOT/.venv/bin/python" ]; then PY="$ROOT/.venv/bin/python"
  elif [ -x "$ROOT/.venv/Scripts/python.exe" ]; then PY="$ROOT/.venv/Scripts/python.exe"
  elif command -v python3 >/dev/null 2>&1 && python3 -c "import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)" 2>/dev/null; then PY=python3
  elif command -v python  >/dev/null 2>&1; then PY=python
  else
    echo "ERROR: no Python 3.10+ interpreter found. Set \$PYTHON to one." >&2
    exit 1
  fi
fi

C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_BLUE=$'\033[36m'
C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'
if [ ! -t 1 ]; then C_RESET=""; C_BOLD=""; C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; fi

say()  { printf '%s\n' "${C_BLUE}${C_BOLD}==>${C_RESET} ${C_BOLD}$*${C_RESET}"; }
ok()   { printf '%s\n' "    ${C_GREEN}ok${C_RESET}   $*"; }
warn() { printf '%s\n' "    ${C_YELLOW}warn${C_RESET} $*"; }
die()  { printf '%s\n' "    ${C_RED}fail${C_RESET} $*" >&2; exit 1; }

HOST="${NETSHIELD_HOST:-127.0.0.1}"
PORT="${NETSHIELD_PORT:-8000}"

# -----------------------------------------------------------------------------
cmd_setup() {
  say "Creating the directory layout"
  mkdir -p data/raw data/processed data/experiments \
           models results/figures results/metrics results/reports results/logs
  ok "directories ready"

  say "Checking dependencies"
  if ! "$PY" -c "import numpy, pandas, sklearn, torch, networkx, matplotlib, yaml" \
        >/dev/null 2>&1; then
    warn "core dependencies are missing; installing from requirements.txt"
    "$PY" -m pip install --disable-pip-version-check -q -r requirements.txt \
      || die "pip install failed - install requirements.txt manually"
  fi
  "$PY" scripts/check_env.py "$@"

  say "Initialising the database"
  "$PY" scripts/init_db.py
  ok "setup complete"
}

cmd_simulate() {
  local exp="${1:-exp2_udp_flood}"; shift || true
  say "Simulating scenario: $exp"
  "$PY" scripts/run_experiment.py --experiment "$exp" "$@"
}

cmd_dataset()     { say "Generating the labelled corpus"; "$PY" scripts/generate_dataset.py "$@"; }
cmd_train()       { say "Training detectors";             "$PY" scripts/train_models.py "$@"; }
cmd_experiments() { say "Running the experiment suite";   "$PY" scripts/run_experiment.py --all "$@"; }
cmd_evaluate()    { say "Evaluating and building reports";"$PY" scripts/evaluate.py "$@"; }
cmd_fuzz()        { say "Running a fuzzing campaign";     "$PY" scripts/fuzz.py "$@"; }
cmd_demo()        { "$PY" scripts/demo.py "$@"; }
cmd_test()        { say "Running the test suite";         "$PY" -m pytest -q "$@"; }

cmd_dashboard() {
  say "Starting the NetShield-GNN API and dashboard"
  printf '\n'
  printf '    %s\n' "${C_BOLD}Dashboard   ${C_RESET} http://${HOST}:${PORT}/"
  printf '    %s\n' "${C_BOLD}Swagger UI  ${C_RESET} http://${HOST}:${PORT}/docs"
  printf '    %s\n' "${C_BOLD}ReDoc       ${C_RESET} http://${HOST}:${PORT}/redoc"
  printf '    %s\n' "${C_BOLD}OpenAPI JSON${C_RESET} http://${HOST}:${PORT}/openapi.json"
  printf '\n    Press Ctrl+C to stop.\n\n'
  "$PY" scripts/serve.py --host "$HOST" --port "$PORT" "$@"
}

cmd_frontend() {
  local mode="${1:-build}"
  command -v npm >/dev/null 2>&1 || die "npm not found; the bundled dashboard at http://${HOST}:${PORT}/ needs no build step."
  say "React frontend: $mode"
  ( cd frontend
    [ -d node_modules ] || npm install
    case "$mode" in
      dev)   npm run dev ;;
      build) npm run build && printf '    built into frontend/dist (served at /app)\n' ;;
      *)     die "unknown frontend mode '$mode' (use dev|build)" ;;
    esac )
}

cmd_all() {
  local started=$SECONDS
  cmd_setup
  say "Step 1/4 - dataset generation (this is the long step, ~10-20 min)"
  "$PY" scripts/generate_dataset.py "$@"
  say "Step 2/4 - training"
  "$PY" scripts/train_models.py
  say "Step 3/4 - experiment suite"
  "$PY" scripts/run_experiment.py --all
  say "Step 4/4 - evaluation, figures and reports"
  "$PY" scripts/evaluate.py
  printf '\n'
  say "Pipeline complete in $(( (SECONDS - started) / 60 )) min $(( (SECONDS - started) % 60 )) s"
  printf '    %s\n' "dataset  : data/processed/dataset.csv"
  printf '    %s\n' "models   : models/"
  printf '    %s\n' "figures  : results/figures/"
  printf '    %s\n' "metrics  : results/metrics/"
  printf '    %s\n' "report   : results/reports/RESULTS.md"
  printf '\n'
  cmd_dashboard
}

cmd_clean() {
  say "Removing generated artefacts"
  rm -rf data/experiments/* data/processed/* data/raw/* data/netshield.db* \
         models/* results/figures/* results/metrics/* results/reports/* results/logs/* \
         2>/dev/null || true
  for d in data/raw data/processed data/experiments models \
           results/figures results/metrics results/reports; do
    mkdir -p "$d"; touch "$d/.gitkeep"
  done
  ok "clean"
}

usage() {
  sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# -----------------------------------------------------------------------------
target="${1:-help}"; shift || true
case "$target" in
  setup)              cmd_setup "$@" ;;
  simulate|sim)       cmd_simulate "$@" ;;
  dataset|data)       cmd_dataset "$@" ;;
  train)              cmd_train "$@" ;;
  experiments|exp)    cmd_experiments "$@" ;;
  evaluate|eval)      cmd_evaluate "$@" ;;
  fuzz)               cmd_fuzz "$@" ;;
  dashboard|serve|api) cmd_dashboard "$@" ;;
  frontend)           cmd_frontend "$@" ;;
  demo)               cmd_demo "$@" ;;
  test|tests)         cmd_test "$@" ;;
  all)                cmd_all "$@" ;;
  clean)              cmd_clean ;;
  help|-h|--help)     usage ;;
  *) printf 'Unknown command: %s\n\n' "$target"; usage; exit 2 ;;
esac
