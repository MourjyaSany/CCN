#!/usr/bin/env python3
"""Score simulation-trained detectors on real packet captures (CICIoT2023).

    python scripts/real_data_eval.py --captures data/external/ciciot2023/*.pcap

Each capture is ingested with :mod:`netshield.realnet.pcap_ingest` (the same
telemetry collector and feature code as the simulator) and scored by every
final model from ``closed_loop_eval.py``.

Because the public captures are labelled per file, not per host, the
evaluation is at two honest levels:

* **Benign capture** - every flag is a false alarm. Reported: host-window
  false-positive rate and flagged hosts.
* **Attack captures** - an attack is known to be running. Reported: share
  of windows in which at least one host is flagged (window-level detection
  rate), and the share of all packets sent by the flagged hosts (are the
  flagged hosts the heavy senders, or random ones?).

Outputs ``results/research/real_data.csv`` and ``real_data_hosts.csv``.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from _bootstrap import banner, common_parser, ok, setup  # noqa: E402


def site_calibration(scores, alphas=(0.05, 0.01)):
    """Calibrate on a site's own benign baseline, then test.

    A deployment records benign traffic before going live. The per-window
    alarm statistic is the maximum hostile score over endpoints. Its
    (1 - alpha) quantile over the *first half* of the benign capture becomes
    the alarm threshold; the window false-alarm rate is measured on the
    *second half*, and the detection rate on every attack capture.
    """
    import numpy as np  # noqa: PLC0415
    import pandas as pd  # noqa: PLC0415

    ep = scores[scores["endpoint"]]
    win = ep.groupby(["capture", "family", "detector", "window"])["hostile"].max().reset_index()
    rows = []
    for det, g in win.groupby("detector"):
        benign = g[g["family"] == "benign"].sort_values("window")
        if len(benign) < 10:
            continue
        half = len(benign) // 2
        calib, held = benign.iloc[:half]["hostile"], benign.iloc[half:]["hostile"]
        for a in alphas:
            thr = float(np.quantile(calib, 1 - a))
            row = {"detector": det, "alpha": a, "threshold": thr,
                   "benign_holdout_window_fpr": float((held > thr).mean())}
            for cap, c in g[g["family"] != "benign"].groupby("family"):
                row[f"detect_{cap}"] = float((c["hostile"] > thr).mean())
            rows.append(row)
    return pd.DataFrame(rows)


def main(argv: list[str] | None = None) -> int:
    parser = common_parser("Evaluate detectors on real captures.")
    parser.add_argument("--captures", nargs="+", required=True)
    parser.add_argument("--models", default="results/research/predictions/final__all")
    parser.add_argument("--detectors", nargs="*",
                        default=["threshold", "random_forest", "lightgbm", "egraphsage",
                                 "graphsage", "temporal_gnn", "autoencoder"])
    parser.add_argument("--max-packets", type=int, default=3_000_000)
    parser.add_argument("--max-seconds", type=float, default=300.0)
    args = parser.parse_args(argv)
    config = setup(args, "real_data_eval")

    import pandas as pd  # noqa: PLC0415

    from netshield.detection.pipeline import load_detectors  # noqa: PLC0415
    from netshield.features.node_features import build_node_window_features  # noqa: PLC0415
    from netshield.graph.builder import build_edge_table  # noqa: PLC0415
    from netshield.models.base import DetectionInput  # noqa: PLC0415
    from netshield.realnet.pcap_ingest import ingest_pcap  # noqa: PLC0415

    trigger = float(config.get("detection.mitigation_trigger_probability", 0.8))
    window_s = float(config.get("features.window_s", 5.0))
    detectors = load_detectors(args.models, args.detectors)
    rows, host_rows, score_rows = [], [], []
    for capture in args.captures:
        path = Path(capture)
        banner(f"Ingesting {path.name}")
        t0 = time.perf_counter()
        view = ingest_pcap(path, window_s=window_s, max_packets=args.max_packets,
                           max_seconds=args.max_seconds)
        features = build_node_window_features(view)
        edges = build_edge_table(view)
        data = DetectionInput(features, edges)
        endpoint = features["kind"].isin(["iot", "attacker"]).to_numpy()
        print(f"  {view.summary['packets']:,} packets, {view.summary['hosts']} hosts, "
              f"{features['window'].nunique()} windows, {len(features):,} rows "
              f"({time.perf_counter() - t0:.0f}s)")
        is_benign = "benign" in path.stem.lower()
        family = path.stem.replace("DDoS-", "").rstrip("0123456789-")
        sent = features.groupby("node_id")["eg_packets"].sum()
        total_sent = float(sent[sent.index != "cloud-0"].sum()) or 1.0
        for name, det in detectors.items():
            t1 = time.perf_counter()
            proba = det.predict_proba(data)
            infer_s = time.perf_counter() - t1
            hostile = proba[:, 1] + proba[:, 2]
            flagged = (hostile >= trigger) & endpoint
            score_rows.append(pd.DataFrame({
                "capture": path.stem, "family": "benign" if is_benign else family,
                "detector": name, "window": features["window"].to_numpy(),
                "node_id": features["node_id"].to_numpy(), "endpoint": endpoint,
                "hostile": hostile}))
            frame = features.loc[endpoint, ["window", "node_id", "eg_packet_rate"]].copy()
            frame["hostile"] = hostile[endpoint]
            frame["flagged"] = flagged[endpoint]
            per_window = frame.groupby("window")["flagged"].any()
            flagged_hosts = sorted(frame.loc[frame["flagged"], "node_id"].unique())
            share = float(sent.reindex(flagged_hosts).fillna(0).sum() / total_sent)
            rows.append({
                "capture": path.stem, "family": "benign" if is_benign else family,
                "detector": name, "packets": view.summary["packets"],
                "hosts": view.summary["hosts"], "windows": int(per_window.size),
                "host_window_flag_rate": float(frame["flagged"].mean()),
                "windows_with_flag": float(per_window.mean()),
                "flagged_hosts": len(flagged_hosts),
                "flagged_hosts_packet_share": share,
                "max_hostile": float(frame["hostile"].max()),
                "infer_us_per_row": infer_s * 1e6 / max(1, len(features)),
            })
            top = frame.groupby("node_id").agg(max_hostile=("hostile", "max"),
                                               flagged_windows=("flagged", "sum"),
                                               mean_pps=("eg_packet_rate", "mean"))
            top = top.sort_values("max_hostile", ascending=False).head(5).reset_index()
            for _, r in top.iterrows():
                host_rows.append({"capture": path.stem, "detector": name, **r.to_dict(),
                                  "packet_share": float(sent.get(r["node_id"], 0) / total_sent)})
            print(f"    {name:<14} flag rate {rows[-1]['host_window_flag_rate']:.4f}  "
                  f"windows flagged {rows[-1]['windows_with_flag']:.3f}  "
                  f"hosts {len(flagged_hosts):>3}  packet share {share:.3f}")
    out = Path("results/research")
    out.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(out / "real_data.csv", index=False)
    pd.DataFrame(host_rows).to_csv(out / "real_data_hosts.csv", index=False)
    scores = pd.concat(score_rows, ignore_index=True)
    scores.to_csv(out / "real_data_scores.csv.gz", index=False)
    site = site_calibration(scores)
    site.to_csv(out / "real_data_site_calibrated.csv", index=False)
    print(site.round(3).to_string(index=False))
    ok(f"real-data results -> {out / 'real_data.csv'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
