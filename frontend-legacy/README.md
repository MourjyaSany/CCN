# NetShield-GNN — React frontend

An optional React + Vite dashboard. **It is not required.** The FastAPI server
already ships a fully functional, dependency-free dashboard at
<http://127.0.0.1:8000/>; this build exists to satisfy the "React + Vite"
requirement and to offer a component-based alternative.

## Build

```bash
cd frontend
npm install
npm run build          # -> frontend/dist, served by FastAPI at /app
```

Then start the API and open <http://127.0.0.1:8000/app>.

## Develop

```bash
npm run dev            # http://localhost:5173, /api proxied to :8000
```

Run the API separately in another terminal:

```bash
./run.sh dashboard
```

## If npm is unavailable or the install fails

Use the bundled dashboard at <http://127.0.0.1:8000/>. It has the same
capabilities — live topology, KPI tiles, time-series charts, alert and
mitigation logs, results browser — implemented in a single self-contained HTML
file with no build step and no third-party JavaScript.
