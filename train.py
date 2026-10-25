"""Train the behavioral classifier from the JSONL log the WAF writes in training mode.

    python -m ml.train --data data/train.jsonl --out models/behavior.json --target-fpr 0.01

Steps (each printed, each reproducible):
  1. split BY SESSION into train/val/test  (rows within a session are highly correlated)
  2. fit StandardScaler + LogisticRegression  (whiteboard-able: weights are the explanation)
  3. BEFORE: evaluate at the naive 0.5 cutoff
  4. TUNE:   pick the lowest threshold on VAL with false-positive-rate <= target
  5. AFTER:  report that threshold on held-out TEST, per attack class
  6. compare against the hand-weighted heuristic baseline
  7. export weights as JSON so the runtime needs no sklearn

Export format is validated against FEATURE_NAMES at load time (see LogisticClassifier).
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from sentinel.detectors.behavior import FEATURE_NAMES, HeuristicClassifier


def load(path: str):
    rows = [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    X = np.array([[r["features"][n] for n in FEATURE_NAMES] for r in rows])
    labels = np.array([r["label"] for r in rows])
    y = (labels != "human").astype(int)  # 1 = bot (any non-human label)
    groups = np.array([r["session"] for r in rows])
    return X, y, labels, groups


def rates(y, p, thr):
    pred = p >= thr
    fp, tn = int(((pred == 1) & (y == 0)).sum()), int(((pred == 0) & (y == 0)).sum())
    fn, tp = int(((pred == 0) & (y == 1)).sum()), int(((pred == 1) & (y == 1)).sum())
    return {"threshold": round(float(thr), 4), "fpr": fp / max(fp + tn, 1),
            "fnr": fn / max(fn + tp, 1), "precision": tp / max(tp + fp, 1),
            "fp": fp, "fn": fn, "tp": tp, "tn": tn}


def pick_threshold(y, p, target_fpr):
    """Lowest threshold whose FPR <= target (maximises recall subject to the FP budget)."""
    for t in np.unique(np.concatenate([p, [1.0 + 1e-9]])):
        if rates(y, p, t)["fpr"] <= target_fpr:
            return float(t)
    return 1.0


def per_label_recall(labels, p, thr):
    out = {}
    for lab in sorted(set(labels) - {"human"}):
        m = labels == lab
        out[str(lab)] = float((p[m] >= thr).mean())
    return out


def fmt(name, r):
    return (f"{name:28} thr={r['threshold']:.3f}  FPR={100*r['fpr']:.2f}%  "
            f"FNR={100*r['fnr']:.2f}%  precision={100*r['precision']:.1f}%  "
            f"(FP={r['fp']} FN={r['fn']})")


def split(groups, seed):
    outer = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=seed)
    tr, rest = next(outer.split(groups, groups=groups))
    inner = GroupShuffleSplit(n_splits=1, test_size=0.5, random_state=seed)
    va, te = next(inner.split(rest, groups=groups[rest]))
    return tr, rest[va], rest[te]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--out", default="models/behavior.json")
    ap.add_argument("--target-fpr", type=float, default=0.01)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()

    X, y, labels, groups = load(a.data)
    if len(set(y)) < 2:
        raise SystemExit("need both human and bot samples (check X-Sim-Label values)")
    tr, va, te = split(groups, a.seed)
    print(f"rows={len(y)} sessions={len(set(groups))}  "
          f"train/val/test={len(tr)}/{len(va)}/{len(te)}  bot_share={y.mean():.2f}")

    scaler = StandardScaler().fit(X[tr])
    clf = LogisticRegression(max_iter=2000, C=1.0).fit(scaler.transform(X[tr]), y[tr])
    prob = lambda idx: clf.predict_proba(scaler.transform(X[idx]))[:, 1]
    p_va, p_te = prob(va), prob(te)

    before = rates(y[te], p_te, 0.5)
    thr = pick_threshold(y[va], p_va, a.target_fpr)
    after = rates(y[te], p_te, thr)
    heur = HeuristicClassifier()
    p_h = np.array([heur.predict_proba(dict(zip(FEATURE_NAMES, row))) for row in X[te]])
    base = rates(y[te], p_h, 0.9)

    print("\nHELD-OUT TEST SET")
    print(fmt("model  @ default 0.5 (before)", before))
    print(fmt(f"model  @ tuned (FPR<={a.target_fpr:.0%})", after))
    print(fmt("heuristic baseline @ 0.9", base))
    print("\nrecall by attack class (model @ tuned):",
          {k: round(v, 3) for k, v in per_label_recall(labels[te], p_te, thr).items()})
    print("recall by attack class (heuristic)    :",
          {k: round(v, 3) for k, v in per_label_recall(labels[te], p_h, 0.9).items()})
    coefs = sorted(zip(FEATURE_NAMES, clf.coef_[0]), key=lambda kv: -abs(kv[1]))
    print("\ntop weights (standardised):", [(n, round(float(c), 2)) for n, c in coefs[:6]])

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "features": list(FEATURE_NAMES), "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(), "coef": clf.coef_[0].tolist(),
        "intercept": float(clf.intercept_[0]), "recommended_threshold": thr}, indent=2))
    (out.parent / "report.json").write_text(json.dumps(
        {"before": before, "after": after, "heuristic": base,
         "recall_by_label": per_label_recall(labels[te], p_te, thr)}, indent=2))
    print(f"\nwrote {out}  -> set SENTINEL_MODEL_PATH={out} SENTINEL_BEHAVIOR_THRESHOLD={thr:.3f}")


if __name__ == "__main__":
    main()
