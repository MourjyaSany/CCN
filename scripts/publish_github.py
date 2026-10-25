#!/usr/bin/env python3
"""Publish this repository to GitHub.

    python scripts/publish_github.py --repo https://github.com/<you>/netshield-gnn.git
    python scripts/publish_github.py --create netshield-gnn --private     # needs the gh CLI

With ``--repo`` the remote must already exist (create an empty repository at
https://github.com/new first). Git Credential Manager opens a browser the
first time to sign you in. With ``--create`` the GitHub CLI (``gh``) creates
the repository and pushes in one step (run ``gh auth login`` once first).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=ROOT, check=check, text=True, capture_output=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repo", help="Existing empty GitHub repository URL.")
    ap.add_argument("--create", metavar="NAME", help="Create the repository with gh.")
    ap.add_argument("--private", action="store_true")
    ap.add_argument("--branch", default="main")
    args = ap.parse_args()
    if not (ROOT / ".git").exists():
        sys.exit("Not a git repository. Run 'git init' and commit first.")
    if git("status", "--porcelain").stdout.strip():
        print("Warning: there are uncommitted changes; only committed work is pushed.")
    if args.create:
        if not shutil.which("gh"):
            sys.exit("The GitHub CLI is not installed: https://cli.github.com/ (or use --repo).")
        vis = "--private" if args.private else "--public"
        subprocess.run(["gh", "repo", "create", args.create, vis, "--source", str(ROOT),
                        "--remote", "origin", "--push"], cwd=ROOT, check=True)
        return 0
    if not args.repo:
        sys.exit("Pass --repo <url> or --create <name>.")
    if git("remote", "get-url", "origin", check=False).returncode == 0:
        git("remote", "set-url", "origin", args.repo)
    else:
        git("remote", "add", "origin", args.repo)
    subprocess.run(["git", "push", "-u", "origin", args.branch], cwd=ROOT, check=True)
    print(f"Pushed to {args.repo}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
