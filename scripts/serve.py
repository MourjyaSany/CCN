#!/usr/bin/env python3
"""Start the NetShield-GNN REST API and dashboard.

The dashboard is served at ``/`` and the interactive OpenAPI documentation at
``/docs``. If the React frontend has been built (``./run.sh frontend build``) it
is additionally mounted at ``/app``.
"""

from __future__ import annotations

import sys

from _bootstrap import banner, common_parser, setup, warn  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Launch the API server.

    Args:
        argv: Command-line arguments.

    Returns:
        Process exit status.
    """
    parser = common_parser("Serve the NetShield-GNN API and dashboard.")
    parser.add_argument("--host", default=None, help="Bind address.")
    parser.add_argument("--port", type=int, default=None, help="Bind port.")
    parser.add_argument("--reload", action="store_true",
                        help="Auto-reload on source changes (development).")
    args = parser.parse_args(argv)

    config = setup(args, "serve")

    try:
        import uvicorn  # noqa: PLC0415
    except ImportError:
        print("\n  uvicorn is not installed. Install it with:\n"
              "      pip install fastapi uvicorn\n")
        return 1

    from netshield.api.app import create_app  # noqa: PLC0415

    host = args.host or str(config.get("api.host", "127.0.0.1"))
    port = int(args.port or config.get("api.port", 8000))

    banner("NetShield-GNN :: API server")
    print(f"  dashboard  : http://{host}:{port}/")
    print(f"  swagger UI : http://{host}:{port}/docs")
    print(f"  redoc      : http://{host}:{port}/redoc")
    print(f"  openapi    : http://{host}:{port}/openapi.json")
    print()

    dataset = config.path("data_processed") / "dataset.csv"
    if not dataset.exists():
        warn("no dataset found - run 'python scripts/generate_dataset.py' to "
             "populate the results view")
    models = config.path("models")
    if not any(models.glob("*/manifest.json")):
        warn("no trained detectors found - run 'python scripts/train_models.py' "
             "to enable live detection and mitigation")

    app = create_app(config)
    uvicorn.run(app, host=host, port=port, log_level=args.log_level.lower(),
                access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
