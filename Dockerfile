# =============================================================================
# NetShield-GNN — reproducible container
#
#   docker compose up                              # dashboard on :8000
#   docker compose run --rm netshield ./run.sh all # full pipeline
#
# CPU-only by design: the models are small and the simulator is single-threaded
# Python, so a GPU buys nothing and a CPU image runs anywhere.
# =============================================================================
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    NETSHIELD_ROOT=/app \
    MPLBACKEND=Agg

# bash for run.sh; curl for the healthcheck. No compiler is required.
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the CPU wheel of torch first so the heavy layer is cached separately
# from the fast-changing application code.
COPY requirements.txt .
RUN pip install --index-url https://download.pytorch.org/whl/cpu "torch>=2.0" \
    && pip install -r requirements.txt

COPY . .

RUN chmod +x run.sh ns3/scripts/build_ns3.sh 2>/dev/null || true \
    && mkdir -p data/raw data/processed data/experiments models \
               results/figures results/metrics results/reports results/logs

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

# The default command serves the dashboard. Override to run the pipeline.
CMD ["python", "scripts/serve.py", "--host", "0.0.0.0", "--port", "8000"]
