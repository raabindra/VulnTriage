# Writeup Notes — Evaluation Framing

Honest, defensible framings for the dissertation's evaluation chapter. Numbers
below were measured live between 2026-07-10 and 2026-07-12 (not just quoted from
cached metadata).

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

## Data-completeness improvements for CWE-less findings

The reweighting experiments above showed that *reweighting* the confidence engine
does not help. The productive lever is instead **improving CWE coverage** at the
data layer — a missing CWE hurts a finding three ways (no catalogue credit, the
CWE→CVSS vector inference can't run so the ML predicts Low, and the `cwe_mapping`
factor scores 0). Two fixes address the two paths a finding gets a CWE.

### (a) NVD enrichment — fixed and extended (for CVE-bearing findings)

Investigating the inert CVE factor surfaced a real bug: `nvd_enrichment` was
**silently non-functional locally** — it looked for `.json` (feeds are `.json.xz`),
used the wrong top-level key (feeds nest under `cve_items`), `json.load`-ed whole
feeds (forbidden on the disk-full box), and resolved the wrong directory. So no
finding ever received NVD CVSS *or* CWE data offline. Fixes:

- **Stream the `.xz` feeds with ijson** (constant memory; only the CVE IDs being
  looked up are cached, so feeds are scanned once per run, not per finding).
- **Back-fill an authoritative `cwe_id` from the NVD `weaknesses` block** when the
  scanner supplied none (prefers the Primary weakness; a scanner CWE is never
  overwritten).
- **Apply NVD's CVSS v3 as one authoritative, consistent set** (score, severity,
  vector, sub-metrics together) instead of updating the score only when unset but
  always overwriting the vector — which previously left a scanner's heuristic
  score (e.g. Nuclei severity→7.5) paired with NVD's vector (which scored 10.0).
  Also stopped nulling scanner-provided CVSS when a CVE has no v3 metrics.

### (b) Keyword→CWE mapper — expanded and de-bugged (for CVE-less web findings)

Web/DAST findings (ZAP alerts, Nuclei detections) often arrive with no CVE, so
the NVD path can't help them; they rely on a static keyword→CWE table. That table
had real defects and thin coverage:

- **Bug — substring acronyms:** `rce` matched "sou**rce**", so "Source Code
  Disclosure" mis-mapped to CWE-94 (RCE). Acronyms are now `\b`-anchored.
- **Bug — cookie catch-all:** a bare `cookie` forced every cookie finding to
  CWE-1004 (HttpOnly); Secure / SameSite / HttpOnly now map distinctly
  (CWE-614 / CWE-1275 / CWE-1004).
- **Ordering:** patterns are explicitly ordered specific→general so a general
  rule can't shadow a specific one (first match wins); patterns are precompiled.
- **Coverage 30→58 patterns** across injection, security headers/cookies/session/
  CORS/config, transport/crypto, auth/credentials, info-disclosure and
  memory-safety tiers.

**Measured:** on 30 common web alerts previously uncovered or mis-mapped, coverage
went **4/30 → 30/30**, with the RCE mis-map fixed.

### End-to-end verification (ingest-based pipeline test)

Live Juice Shop autoscans do **not** exercise either fix (Juice Shop yields no
CVEs, and ZAP supplies its own CWE for its alerts), so both were verified by
running the *actual pipeline engines* over crafted inputs: a ZAP report with no
`<cweid>` and mappable titles, plus a Nuclei finding with a CVE but no CWE and a
non-mappable name. Result: the three ZAP findings were filled by the **keyword
mapper** (incl. Source Code Disclosure → CWE-540, the regression case), and the
Nuclei finding was filled by **NVD back-fill** (CWE-1188 + a CVSS vector/score that
now agree at 10.0). Correct boundary preserved: pure detection/informational
templates (e.g. "Modern Web Application") still map to nothing — they are not
weaknesses, so forcing a CWE would add noise.

**Honest scope note:** the NVD back-fill only helps findings that carry a CVE
(Nessus, some Nuclei); pure-ZAP web findings still depend on the keyword mapper.
That is the correct boundary, not a gap.

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
