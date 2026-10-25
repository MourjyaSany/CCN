#!/usr/bin/env python3
"""Create (or reset) the SQLite database used by the dashboard and reports."""

from __future__ import annotations

import sys

from _bootstrap import banner, common_parser, ok, setup  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Initialise the database.

    Args:
        argv: Command-line arguments.

    Returns:
        Process exit status.
    """
    parser = common_parser("Initialise the NetShield-GNN SQLite database.")
    parser.add_argument("--reset", action="store_true",
                        help="Delete every row while preserving the schema.")
    parser.add_argument("--path", default=None, help="Override the database path.")
    args = parser.parse_args(argv)

    config = setup(args, "init_db")

    from netshield.database.schema import SCHEMA_VERSION  # noqa: PLC0415
    from netshield.database.store import init_database  # noqa: PLC0415

    path = args.path or config.path("database")
    banner("NetShield-GNN :: database")
    db = init_database(path)
    ok(f"schema v{SCHEMA_VERSION} ready at {db.path}")

    if args.reset:
        db.reset()
        ok("all rows deleted")

    counts = db.table_counts()
    print("\n  table row counts:")
    for table, count in counts.items():
        print(f"    {table:<20} {count:>8,}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
