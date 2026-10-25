"""Per-alert explanations: why did the detector flag this node?

Two methods, chosen by detector type:

Integrated Gradients (Sundararajan, Taly and Yan, ICML 2017) - graph models
    The node's hostile logit-probability is integrated along a straight path
    from a baseline (all features at the training mean, i.e. zero in scaled
    space) to the observed window. The gradient is taken with respect to the
    feature matrix of **every** node in the window graph, so the result
    splits into (a) attributions of the node's own features and (b) the total
    attribution flowing in from each neighbour. Attributions satisfy
    completeness: they sum to ``score(x) - score(baseline)`` up to the
    Riemann error reported as ``completeness_gap``.

Feature-group occlusion - any detector
    Each feature group of the node is replaced by the median across the
    window's nodes ("what a typical peer looks like right now") and the change
    in the node's hostile score is recorded. Model-agnostic and cheap.

Both return the same structure so the dashboard renders them identically.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from .models.base import DetectionInput, Detector


def _groups() -> dict[str, tuple[str, ...]]:
    from .research.protocol import FEATURE_GROUPS  # noqa: PLC0415

    return FEATURE_GROUPS


def occlusion(detector: Detector, data: DetectionInput, node: str) -> dict[str, Any]:
    """Feature-group occlusion for *node* in a single-window input."""
    frame = data.features
    row = np.nonzero((frame["node_id"] == node).to_numpy())[0]
    if not len(row):
        raise KeyError(f"Node {node!r} not present in this window")
    i = int(row[0])
    base = float(detector.attack_probability(data)[i])
    # Baseline: the median node of the same window ("a typical peer now").
    groups = []
    for name, cols in _groups().items():
        masked = frame.copy()
        for c in cols:
            if c in masked.columns:
                masked.loc[i, c] = float(frame[c].median())
        score = float(detector.attack_probability(DetectionInput(masked, data.edges))[i])
        groups.append({"group": name, "delta": round(base - score, 5)})
    groups.sort(key=lambda g: -abs(g["delta"]))
    return {"method": "occlusion", "node": node, "score": round(base, 5),
            "feature_groups": groups, "features": [], "neighbours": []}


def integrated_gradients(detector: Any, data: DetectionInput, node: str,
                         steps: int = 48, top_k: int = 10) -> dict[str, Any]:
    """Integrated-gradients attribution for a GraphSAGE-family detector."""
    import torch  # noqa: PLC0415
    import torch.nn.functional as F  # noqa: PLC0415

    from .models.graphsage import _collate  # noqa: PLC0415

    graphs = detector._build(data)
    graph = next((g for g in graphs if node in g.node_ids), None)
    if graph is None:
        raise KeyError(f"Node {node!r} not present in this window")
    target = graph.node_ids.index(node)
    x, ei, _, ea = _collate([graph], torch.device("cpu"))
    model = detector.model.eval()
    baseline = torch.zeros_like(x)

    def hostile(inp: torch.Tensor) -> torch.Tensor:
        p = F.softmax(model(inp, ei, ea), dim=1)
        return p[target, 1] + p[target, 2]

    total = torch.zeros_like(x)
    for alpha in torch.linspace(1.0 / steps, 1.0, steps):
        inp = (baseline + alpha * (x - baseline)).requires_grad_(True)
        grad, = torch.autograd.grad(hostile(inp), inp)
        total += grad
    attr = ((x - baseline) * total / steps).detach().numpy()
    with torch.no_grad():
        score, score0 = float(hostile(x)), float(hostile(baseline))
    gap = float(attr.sum() - (score - score0))
    cols = list(detector.feature_columns)
    raw = data.features.set_index("node_id").loc[node]
    own = attr[target]
    order = np.argsort(-np.abs(own))[:top_k]
    features = [{"feature": cols[j], "attribution": round(float(own[j]), 5),
                 "value": float(raw[cols[j]]) if cols[j] in raw else None} for j in order]
    neigh = []
    for j, nid in enumerate(graph.node_ids):
        if j == target:
            continue
        a = float(attr[j].sum())
        if abs(a) > 1e-6:
            neigh.append({"node": nid, "kind": graph.kinds[j] if j < len(graph.kinds) else "",
                          "attribution": round(a, 5)})
    neigh.sort(key=lambda n: -abs(n["attribution"]))
    groups = []
    for name, gcols in _groups().items():
        idx = [cols.index(c) for c in gcols if c in cols]
        groups.append({"group": name, "delta": round(float(own[idx].sum()), 5)})
    groups.sort(key=lambda g: -abs(g["delta"]))
    return {"method": "integrated_gradients", "node": node, "score": round(score, 5),
            "baseline_score": round(score0, 5), "completeness_gap": round(gap, 6),
            "self_attribution": round(float(own.sum()), 5),
            "neighbour_attribution": round(float(attr.sum() - own.sum()), 5),
            "features": features, "neighbours": neigh[:top_k], "feature_groups": groups}


def explain(detector: Detector, data: DetectionInput, node: str) -> dict[str, Any]:
    """Explain *node*'s score, picking the best method for the detector."""
    if getattr(detector, "uses_graph", False) and hasattr(detector, "_build") and \
            detector.__class__.__name__ != "TemporalGNNDetector":
        return integrated_gradients(detector, data, node)
    return occlusion(detector, data, node)
