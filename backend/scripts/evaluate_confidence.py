"""
Confidence Engine evaluation harness.

Runs the ConfidenceEngine over a curated labelled benchmark (see
app/engines/eval/labelled_findings.py — note its honesty caveat) and reports how
well the confidence score separates true positives from false positives:

  • ROC-AUC of score vs ground-truth true-positive
  • Mean score: TP vs FP (separation)
  • "Confirmed" (>=70) precision / recall / F1 as a TP detector
  • Operational triage view: false-positive suppression, TP retention, and
    analyst workload reduction if "Not Confirmed" (<40) is auto-dismissed
  • A threshold sweep
  • A weight sensitivity analysis (AUC under alternative weightings)

Run:
  cd backend && python -m scripts.evaluate_confidence
Outputs a console report and writes reports_output/confidence_eval.{md,json}.

No Flask app context or database is required — the engine's compute_score is
pure and runs on lightweight stand-in findings.
"""

import os
import sys
import json

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from app.engines.confidence_engine import ConfidenceEngine
from app.engines.eval.labelled_findings import build_benchmark


# ---------------------------------------------------------------------------
#  Metric helpers (dependency-free)
# ---------------------------------------------------------------------------
def roc_auc(scores, labels):
    """Mann–Whitney U / rank interpretation of ROC-AUC. labels are bool TP."""
    pos = [s for s, l in zip(scores, labels) if l]
    neg = [s for s, l in zip(scores, labels) if not l]
    if not pos or not neg:
        return float("nan")
    wins = 0.0
    for p in pos:
        for n in neg:
            wins += 1.0 if p > n else 0.5 if p == n else 0.0
    return wins / (len(pos) * len(neg))


def prf(predicted_pos, labels):
    """precision/recall/F1 where predicted_pos[i] & labels[i] are bool."""
    tp = sum(1 for p, l in zip(predicted_pos, labels) if p and l)
    fp = sum(1 for p, l in zip(predicted_pos, labels) if p and not l)
    fn = sum(1 for p, l in zip(predicted_pos, labels) if not p and l)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    return prec, rec, f1


def mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


# ---------------------------------------------------------------------------
#  Core evaluation
# ---------------------------------------------------------------------------
def score_benchmark(weights=None):
    engine = ConfidenceEngine(weights=weights)
    findings = build_benchmark()
    rows = []
    for f in findings:
        score, classification, _ = engine.compute_score(f)
        rows.append({
            "title": f.title,
            "tp": f.is_true_positive,
            "score": score,
            "classification": classification,
        })
    return rows


def evaluate():
    rows = score_benchmark()
    scores = [r["score"] for r in rows]
    labels = [r["tp"] for r in rows]
    n_tp = sum(labels)
    n_fp = len(labels) - n_tp

    auc = roc_auc(scores, labels)
    tp_mean = mean([r["score"] for r in rows if r["tp"]])
    fp_mean = mean([r["score"] for r in rows if not r["tp"]])

    # "Confirmed" (>=70) as a true-positive detector
    confirmed_pred = [r["score"] >= 70 for r in rows]
    c_prec, c_rec, c_f1 = prf(confirmed_pred, labels)

    # Operational triage: auto-dismiss "Not Confirmed" (<40)
    dismissed = [r["score"] < 40 for r in rows]
    fp_suppressed = sum(1 for d, l in zip(dismissed, labels) if d and not l)
    tp_dismissed = sum(1 for d, l in zip(dismissed, labels) if d and l)
    fp_suppression_rate = fp_suppressed / n_fp if n_fp else 0.0
    tp_retention_rate = 1 - (tp_dismissed / n_tp) if n_tp else 0.0
    workload_reduction = sum(dismissed) / len(rows)

    # Threshold sweep — at each t, "flag for analyst" = score >= t
    sweep = []
    for t in [20, 30, 40, 50, 60, 70, 80, 90]:
        flagged = [s >= t for s in scores]
        p, r, f1 = prf(flagged, labels)
        # FPs filtered out (not flagged)
        fp_filtered = sum(1 for fl, l in zip(flagged, labels) if not fl and not l)
        sweep.append({
            "threshold": t, "tp_recall": round(r, 3),
            "precision": round(p, 3), "f1": round(f1, 3),
            "fp_filtered_pct": round(100 * fp_filtered / n_fp, 1) if n_fp else 0.0,
        })

    # Weight sensitivity
    schemes = {
        "default":       None,
        "equal":         {k: 100 / 6 for k in ConfidenceEngine.WEIGHTS},
        "no_severity":   {"scanner_agreement": 30, "severity_consistency": 0,
                          "cve_availability": 20, "exploit_availability": 20,
                          "poc_validation": 20, "cwe_mapping": 10},
        "poc_heavy":     {"scanner_agreement": 20, "severity_consistency": 10,
                          "cve_availability": 15, "exploit_availability": 15,
                          "poc_validation": 30, "cwe_mapping": 10},
        "scanner_heavy": {"scanner_agreement": 40, "severity_consistency": 15,
                          "cve_availability": 15, "exploit_availability": 10,
                          "poc_validation": 10, "cwe_mapping": 10},
    }
    sensitivity = {}
    for name, w in schemes.items():
        r = score_benchmark(w)
        sensitivity[name] = round(roc_auc([x["score"] for x in r],
                                          [x["tp"] for x in r]), 3)

    return {
        "benchmark_size": len(rows),
        "true_positives": n_tp,
        "false_positives": n_fp,
        "roc_auc": round(auc, 3),
        "mean_score_tp": round(tp_mean, 1),
        "mean_score_fp": round(fp_mean, 1),
        "confirmed_threshold_70": {
            "precision": round(c_prec, 3), "recall": round(c_rec, 3),
            "f1": round(c_f1, 3),
        },
        "operational_triage": {
            "fp_suppression_rate": round(fp_suppression_rate, 3),
            "tp_retention_rate": round(tp_retention_rate, 3),
            "analyst_workload_reduction": round(workload_reduction, 3),
        },
        "threshold_sweep": sweep,
        "weight_sensitivity_auc": sensitivity,
        "rows": rows,
    }


# ---------------------------------------------------------------------------
#  Reporting
# ---------------------------------------------------------------------------
def render_markdown(m) -> str:
    L = []
    L.append("# Confidence Engine — Evaluation Report\n")
    L.append("> **Curated synthetic benchmark** (not field-validated). See "
             "`app/engines/eval/labelled_findings.py` for provenance.\n")
    L.append(f"- Benchmark: **{m['benchmark_size']}** scenarios "
             f"({m['true_positives']} true positives, {m['false_positives']} false positives)")
    L.append(f"- **ROC-AUC (score vs true-positive): {m['roc_auc']}**")
    L.append(f"- Mean confidence — true positives **{m['mean_score_tp']}** vs "
             f"false positives **{m['mean_score_fp']}** "
             f"(separation {round(m['mean_score_tp'] - m['mean_score_fp'], 1)})\n")
    c = m["confirmed_threshold_70"]
    L.append("## 'Confirmed' (score ≥ 70) as a true-positive detector")
    L.append(f"- Precision **{c['precision']}**, Recall **{c['recall']}**, F1 **{c['f1']}**\n")
    o = m["operational_triage"]
    L.append("## Operational triage (auto-dismiss 'Not Confirmed' < 40)")
    L.append(f"- False-positive suppression: **{round(o['fp_suppression_rate']*100,1)}%** of FPs auto-dismissed")
    L.append(f"- True-positive retention: **{round(o['tp_retention_rate']*100,1)}%** of TPs kept for review")
    L.append(f"- Analyst workload reduction: **{round(o['analyst_workload_reduction']*100,1)}%** of findings auto-dismissed\n")
    L.append("## Threshold sweep")
    L.append("| Threshold | TP recall | Precision | F1 | FPs filtered |")
    L.append("|----------:|----------:|----------:|----:|-------------:|")
    for s in m["threshold_sweep"]:
        L.append(f"| {s['threshold']} | {s['tp_recall']} | {s['precision']} | "
                 f"{s['f1']} | {s['fp_filtered_pct']}% |")
    L.append("\n## Weight sensitivity (ROC-AUC under alternative weightings)")
    L.append("| Weighting | ROC-AUC |")
    L.append("|-----------|--------:|")
    for name, auc in m["weight_sensitivity_auc"].items():
        L.append(f"| {name} | {auc} |")
    L.append("")
    return "\n".join(L)


def main():
    m = evaluate()
    out_dir = os.path.join(_BACKEND_DIR, "reports_output")
    os.makedirs(out_dir, exist_ok=True)
    md = render_markdown(m)
    with open(os.path.join(out_dir, "confidence_eval.md"), "w") as f:
        f.write(md)
    with open(os.path.join(out_dir, "confidence_eval.json"), "w") as f:
        json.dump(m, f, indent=2)

    print(md)
    print(f"\nWrote {out_dir}/confidence_eval.md and .json")


if __name__ == "__main__":
    main()
