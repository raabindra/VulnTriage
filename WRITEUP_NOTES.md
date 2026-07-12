# Writeup Notes — Evaluation Framing

Honest, defensible framings for the dissertation's evaluation chapter. Numbers
below were measured live on 2026-07-10 (not just quoted from cached metadata).

## Confidence Engine — false-positive handling

**Framing to use:** *On the false-positive half of the curated benchmark, the
Confidence Engine wrongly confirmed 0/16 and auto-dismissed 13/16; the 3 residual
cases were routed to manual review rather than mis-triaged — the safe failure
mode.*

Why this matters (and why "16 false positives" is a strength, not a weakness):

- The 16 FPs are **ground truth in the test set** — realistic scanner alarms that
  are *not* real vulnerabilities (lone "missing X-Frame-Options", server version
  banner, "possible SQLi" where the PoC failed, a version-based CVE match on a
  host that is actually patched, etc.). They are the noise the engine is *meant*
  to suppress, not errors the engine produced.
- A false-positive-suppression metric is only meaningful if the benchmark
  *contains* false positives. The 16 TP / 16 FP balance also keeps ROC-AUC
  honest (an imbalanced set would flatter a naive "always true-positive" scorer).

Measured outcome on the 16 FPs (Confidence Engine, default weights):

| Outcome | Count | Interpretation |
|---|---|---|
| Wrongly Confirmed (≥70) | **0** | The dangerous error — never occurs. "Confirmed" precision = 1.0 |
| Needs manual review (40–69) | 3 | Safe: a human still verifies, nothing auto-actioned |
| Auto-dismissed (<40) | 13 | Correctly discarded with no analyst effort |

Mean FP confidence = 32.0 (below the 40 dismissal line). The 3 that reach the
review band are the deliberately-hard, overlapping cases the benchmark plants so
it is not trivially separable — most notably a version-based CVE match on a
patched host (score 68.3), where every *automatable* signal (real CVE, real CWE,
network attack vector) says "real"; only the host being patched makes it a false
positive, which cannot be known without active probing. Routing that to a human
is the correct, conservative triage outcome.

**Takeaway line:** the engine avoids the two costly mistakes — auto-confirming
junk and auto-dismissing a real vulnerability — and degrades to human review on
the genuinely ambiguous cases.

Caveat to state explicitly: this is a **curated synthetic benchmark** (the eval
harness flags this itself), reported as "N of 32 scenarios", not as
field-validated accuracy. Strongest next step: label a set of real multi-scanner
findings and re-run the same harness. (Ties to the "more real-world labelled
data" backlog item.)

## Confidence Engine — reweighting experiments (negative result)

The `cve_availability` factor (weight 15) is binary on CVE-*presence*, so on a
pure web-app (ZAP) scan — where findings carry no CVE — it scores 0 for every
finding and contributes no discrimination ("inert"). Two schemes were tested on
the 32-case benchmark to reclaim that weight:

1. **Renormalization** — drop the inert factor and redistribute its weight across
   the applicable factors. Result: AUC 0.822 → 0.830 (within the 0.809–0.826
   noise band), Confirmed-recall +6pp, but FP auto-dismissal **fell** 81%→75%.
2. **CVE-or-CWE partial credit** — give CWE-only findings partial catalogue
   credit (40/50/60). Result: **worse** — TP/FP separation dropped (29.7→~28) and
   FP suppression fell to 75%, AUC flat within noise.

**Conclusion:** neither helps; the binary-CVE baseline is best on the operating
metric (FP suppression @40 = 81%). Root cause: catalogue *presence* (CVE or CWE)
is nearly universal across both TPs and FPs (15/16 vs 13/16 have a CWE), so it is
non-discriminating. **The engine's separating power comes from scanner agreement
+ PoC + severity consistency, not catalogue presence.** Defensible finding: we
tested and rejected two plausible reweightings with evidence.

## NVD enrichment fix — the productive lever for CWE-less findings

Investigating the inert CVE factor surfaced a real bug: `nvd_enrichment` was
**silently non-functional locally** — it looked for `.json` (feeds are `.json.xz`),
used the wrong top-level key, `json.load`-ed whole feeds (forbidden on the
disk-full box), and resolved the wrong directory. So no finding ever received NVD
CVSS *or* CWE data offline. Fixed to stream the `.xz` feeds with ijson (constant
memory, wanted-ID cache) and to **back-fill an authoritative `cwe_id` from the NVD
`weaknesses` block** when the scanner supplied none. Verified offline: a
CVE-bearing finding with no CWE/CVSS gains CWE + full CVSS vector. This is the
right way to help CWE-less findings (a correct data-completeness fix), as opposed
to reweighting, which the experiments above showed does not help.

## ML prioritiser (Random Forest) — accuracy caveat

Measured on the deployed `random_forest.pkl`, scored on 21,697 real held-out NVD
rows (stratified split, seed 42): **accuracy 0.9968, macro-F1 0.9941** — matches
the stored `model_meta.json` to the digit, confirming the pickled model
reproduces its reported metrics. All 70 misclassifications are off-by-one severity
band (never a wild miss).

**Honest framing:** the ~99.7% is legitimate (no target leakage — `cvss_score`
itself is excluded from the features), but the label (severity band) is a
*deterministic* function of the CVSS sub-metrics the model consumes, so the model
is essentially relearning the CVSS scoring formula, with errors only at band
boundaries. `cwe_number` (top feature, ~0.25 importance) is the one genuinely
non-deterministic signal. The high number reflects a near-deterministic task, not
a hard prediction problem.

**Where the real ML contribution lives:** the Confidence Engine (ROC-AUC ≈ 0.82
on a deliberately non-separable benchmark), which predicts something CVSS cannot
give — the likelihood a finding is a true positive. Predicting exploitability
(e.g. EPSS) is the stated future-work lever.
