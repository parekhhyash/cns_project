"""Train, evaluate, save and use the certificate risk model."""
from __future__ import annotations

import json
import logging
import os
import time

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from ..analyzer import Analyzer
from . import dataset
from .features import DESCRIPTIONS, NAMES, extract, vector

HERE = os.path.dirname(__file__)
MODEL_PATH = os.path.join(HERE, "model.joblib")
METRICS_PATH = os.path.join(HERE, "metrics.json")
THRESHOLD = 0.5
SEED = 7


def _matrix(samples):
    now = None
    X = np.array([vector(extract(s.chain, s.host, now)) for s in samples])
    y = np.array([s.label for s in samples])
    return X, y


def _rf():
    return RandomForestClassifier(n_estimators=150, min_samples_leaf=2, n_jobs=-1,
                                  class_weight="balanced_subsample", random_state=SEED)


def train(seed: int = SEED, quiet: bool = False) -> dict:
    log = (lambda *a: None) if quiet else print
    logging.getLogger("certlab.decision").disabled = True   # thousands of BLOCK lines otherwise
    t0 = time.time()
    factory, main, blind = dataset.build(seed=seed)
    log(f"generated {len(main)} training-kind + {len(blind)} blind-spot certificates "
        f"in {time.time() - t0:.1f}s")

    rules = Analyzer([factory.root.cert], crls=[factory.crl()], ct_log=factory.ct)

    def rule_block(s):
        return not rules.analyze(s.chain, s.host).allow

    X, y = _matrix(main)
    kinds = np.array([s.kind for s in main])
    idx = np.arange(len(main))
    tr, te = train_test_split(idx, test_size=0.25, stratify=kinds, random_state=seed)

    clf = _rf().fit(X[tr], y[tr])
    base = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced"))
    base.fit(X[tr], y[tr])

    cv = StratifiedKFold(5, shuffle=True, random_state=seed)
    cv_rf = cross_val_score(_rf(), X[tr], y[tr], cv=cv, scoring="f1")
    cv_lr = cross_val_score(make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
                            X[tr], y[tr], cv=cv, scoring="f1")

    p = clf.predict_proba(X[te])[:, 1]
    pred = (p >= THRESHOLD).astype(int)
    p_lr = base.predict_proba(X[te])[:, 1]
    fpr, tpr, _ = roc_curve(y[te], p)
    step = max(len(fpr) // 60, 1)

    def block_metrics(yt, yp, pp):
        return {"accuracy": accuracy_score(yt, yp), "precision": precision_score(yt, yp),
                "recall": recall_score(yt, yp), "f1": f1_score(yt, yp), "auc": roc_auc_score(yt, pp)}

    # ---- rules vs ML vs hybrid, per attack kind ------------------------------
    test_samples = [main[i] for i in te]
    rule_flags = {id(s): rule_block(s) for s in test_samples + blind}
    ml_p = dict(zip((id(s) for s in test_samples), p))
    if blind:
        Xb, _ = _matrix(blind)
        ml_p.update(zip((id(s) for s in blind), clf.predict_proba(Xb)[:, 1]))

    def rate(sub, who):
        if not sub:
            return 0.0
        n = 0
        for s in sub:
            r, m = rule_flags[id(s)], ml_p[id(s)] >= THRESHOLD
            n += {"rules": r, "ml": m, "hybrid": r or m}[who]
        return n / len(sub)

    per_kind = []
    for k, desc in {**dataset.TRAIN_ATTACKS, **dataset.BLIND_KINDS}.items():
        sub = [s for s in test_samples + blind if s.kind == k]
        per_kind.append({"kind": k, "description": desc, "n": len(sub),
                         "blind_spot": k in dataset.BLIND_KINDS,
                         "rules": rate(sub, "rules"), "ml": rate(sub, "ml"),
                         "hybrid": rate(sub, "hybrid")})
    benign = [s for s in test_samples if s.kind == "benign"]
    fp = {w: float(rate(benign, w)) for w in ("rules", "ml", "hybrid")}
    macro = {w: float(np.mean([r[w] for r in per_kind])) for w in ("rules", "ml", "hybrid")}

    imp = sorted(zip(NAMES, clf.feature_importances_), key=lambda t: -t[1])
    benign_median = np.median(X[tr][y[tr] == 0], axis=0)

    metrics = {
        "trained_at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()),
        "seed": seed,
        "dataset": {"total": len(main) + len(blind), "train": int(len(tr)), "test": int(len(te)),
                    "blind_spot": len(blind), "features": len(NAMES),
                    "benign": int((y == 0).sum()), "malicious": int((y == 1).sum())},
        "threshold": THRESHOLD,
        "random_forest": {**block_metrics(y[te], pred, p),
                          "cv_f1_mean": float(cv_rf.mean()), "cv_f1_std": float(cv_rf.std())},
        "logistic_regression": {**block_metrics(y[te], (p_lr >= THRESHOLD).astype(int), p_lr),
                                "cv_f1_mean": float(cv_lr.mean()), "cv_f1_std": float(cv_lr.std())},
        "confusion": confusion_matrix(y[te], pred).tolist(),   # [[TN, FP], [FN, TP]]
        "roc": {"fpr": [round(float(v), 4) for v in fpr[::step]],
                "tpr": [round(float(v), 4) for v in tpr[::step]]},
        "per_kind": per_kind,
        "false_alarm": fp,
        "catch_rate_macro": macro,
        "importance": [{"feature": n, "importance": float(v), "description": DESCRIPTIONS[n]}
                       for n, v in imp],
    }
    joblib.dump({"model": clf, "baseline": benign_median, "names": NAMES}, MODEL_PATH, compress=3)
    with open(METRICS_PATH, "w") as f:
        json.dump(metrics, f, indent=1)
    log(f"RF test F1={metrics['random_forest']['f1']:.3f}  AUC={metrics['random_forest']['auc']:.3f}  "
        f"CV F1={cv_rf.mean():.3f}±{cv_rf.std():.3f}  (LogReg F1={metrics['logistic_regression']['f1']:.3f})")
    log(f"macro catch-rate  rules={macro['rules']:.2f}  ml={macro['ml']:.2f}  hybrid={macro['hybrid']:.2f}   "
        f"false alarms  rules={fp['rules']:.3f} ml={fp['ml']:.3f} hybrid={fp['hybrid']:.3f}")
    logging.getLogger("certlab.decision").disabled = False
    return metrics


class RiskModel:
    """Loaded model with explanations."""

    def __init__(self, path: str = MODEL_PATH):
        bundle = joblib.load(path)
        self.clf, self.baseline, self.names = bundle["model"], bundle["baseline"], bundle["names"]

    def score(self, chain, host, top: int = 5) -> dict:
        feats = extract(chain, host)
        x = np.array([vector(feats)])
        prob = float(self.clf.predict_proba(x)[0, 1])
        # local explanation: how much does the risk drop if this one feature looked typical?
        variants = np.repeat(x, len(self.names), axis=0)
        for i in range(len(self.names)):
            variants[i, i] = self.baseline[i]
        drops = prob - self.clf.predict_proba(variants)[:, 1]
        order = np.argsort(-drops)[:top]
        reasons = [{"feature": self.names[i], "description": DESCRIPTIONS[self.names[i]],
                    "value": feats[self.names[i]], "typical": float(self.baseline[i]),
                    "effect": float(drops[i])} for i in order if drops[i] > 0.01]
        return {"risk": prob, "flag": prob >= THRESHOLD, "threshold": THRESHOLD,
                "reasons": reasons, "features": feats}
