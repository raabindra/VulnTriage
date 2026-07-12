# VulnTriage — System & Progress Summary

> A reference overview of the system and the work completed. Last updated 2026-07-12.

## 1. What the system is

**VulnTriage** — *"AI-Assisted Vulnerability Triage and Confirmation System Using ML
and Multi-Scanner Analysis"* — is a final-year project at `/home/kali/FYP`. Its core
purpose is **not scanning** but **triage**: it ingests the output of established
scanners (OWASP ZAP, Nuclei, Nessus) and turns a noisy pile of raw findings into a
**prioritised, confidence-scored, evidence-backed shortlist**, so an analyst can tell
real vulnerabilities from false positives quickly. An optional layer can also *drive*
ZAP/Nuclei against an authorised target and feed the results into the same pipeline.

## 2. Architecture & tech stack

| Layer | Technology |
|---|---|
| **Front end** | React 18 + Vite + Tailwind (single-page app) |
| **Backend / API** | Flask + SQLAlchemy 2.x, JWT auth |
| **Database** | PostgreSQL (web) or SQLite (desktop/CLI) — same schema, generic column types |
| **ML** | Pure-NumPy Random Forest (inference needs only NumPy; scikit-learn is training-only) |
| **Runs as** | (1) Desktop app (pywebview + SQLite), (2) Docker web app (`localhost:5000` + Postgres), (3) CLI |

It is a **layered, service-oriented** design: three interchangeable front ends → Flask
API → independent single-responsibility **engine services** → SQLAlchemy data layer,
plus supporting resources (the trained model, offline NVD feeds, external scanner
binaries).

## 3. The triage pipeline (the heart of the system)

Findings flow through these engines in a fixed order (in `backend/app/engines/`):

```
normalisation → deduplication → cwe_mapper → nvd_enrichment
  → cwe_cvss_enrichment → ml/predictor → confidence_engine
  → (optional) poc_validator → report_generator
```

- **Normalisation** — unifies severity/CWE/fields (drops `CWE-0` placeholders, strips HTML from descriptions).
- **Deduplication** — SHA-256 `group_hash`; merges the *same* issue across scanners → raises `scanner_count`.
- **CWE mapper** — 58-pattern keyword table fills a weakness class when the scanner gave none.
- **NVD enrichment** — streams offline NVD `.xz` feeds to fill authoritative CVSS vectors **and back-fill CWE** for CVE-bearing findings.
- **CWE→CVSS enrichment** — derives a plausible CVSS vector from the CWE for vector-less (ZAP) findings, so the ML model gets real features.
- **ML predictor** — Random Forest predicts the severity band.
- **Confidence engine** — the novel part (see §5).
- **PoC validator** — non-destructive checks (XSS, SQLi error/boolean/time-blind, open-redirect, LFI, headers, CORS) with an authorisation **scope guard**; a confirmed PoC overrides to *Confirmed*.
- **Report generator** — PDF triage report.

## 4. The ML prioritiser

Pure-NumPy Random Forest trained on **108,495** real CVSS-v3 records (NVD JSON feeds,
2023–25), predicting the severity band from the **8 CVSS sub-metrics + CWE** —
deliberately **excluding the CVSS base score** (that would be target leakage).
**Accuracy 0.9968 / macro-F1 0.9941** on 21,697 held-out rows (live re-verified, matches
the stored model metadata to the digit). Honest caveat: the CVSS score is deterministic
from its sub-metrics, so the model largely relearns the CVSS formula — legitimate but
near-deterministic.

## 5. The Confidence Engine (the genuinely novel contribution)

Instead of severity, it estimates **the likelihood a finding is a true positive** —
something CVSS cannot give. Six reliability factors, weighted to 100: scanner agreement
(25), severity consistency (20), CVE availability (15), exploit availability (15), PoC
validation (15), CWE mapping (10). Output 0–100 → **≥70 Confirmed / 40–69 Needs Manual
Verification / <40 Not Confirmed**. Every score carries a per-factor breakdown +
plain-language rationale (shown in the UI and PDF). On its curated benchmark: **ROC-AUC
≈ 0.82**, precision 1.0 for "Confirmed", ~81% false-positive suppression.

## 6. Database (9 tables)

`users → scanner_uploads → vulnerabilities → normalized_findings`, with
`confidence_scores`, `ml_predictions`, `poc_validations` hanging off findings, plus
`reports` and a `cwe_mappings` reference table. (See the ERD in
`CHAPTER_4_DESIGN_AND_IMPLEMENTATION.md`.)

---

## 7. Work completed (recent session)

Ten commits (`3e70362` → `63ad299`), all pushed to `main`.

### A. Reliability & correctness fixes

| Commit | What |
|---|---|
| `3e70362` | **Fixed the VM crash** — root cause was 3.1 GB of stale ZAP sessions on a near-full disk (not concurrency). Cleared them + added a disk pre-flight guard and `-Xmx2g` heap cap so ZAP can't exhaust the box. **Also fixed a silent PoC false-negative**: `--scope localhost:3000` (host:port) matched nothing, so all PoC checks were silently skipped → 0 confirmations. |
| `90e7321` | **Fixed silently-inert NVD enrichment** — it read `.json` (feeds are `.json.xz`), used the wrong key/dir, and would have blown memory. Rewrote to stream `.xz` with ijson (constant memory) and **back-fill CWE from NVD `weaknesses`**. |
| `0caffee` | **Made NVD CVSS consistent** — score+vector+sub-metrics now applied as one authoritative set (was leaving a scanner's 7.5 next to NVD's 10.0 vector); stopped nulling scanner CVSS when a CVE has no v3 metrics. |
| `78c1374` | **Expanded + de-bugged the CWE mapper** — 30→58 patterns; fixed `rce` matching "sou**rce**" and the `cookie` catch-all; coverage on common web alerts went 4/30 → 30/30. |
| `e2d7613` | **Normalized `CWE-0`** (ZAP's "no weakness" placeholder) to `None` so it no longer blocks the mapper/NVD or earns phantom confidence credit. |
| `6c57ba1` | **Stripped HTML** from scanner descriptions/solutions (raw `<p>` tags) at the normalisation chokepoint — fixes both UI and PDF. |

### B. Analysis (a documented negative result)

Investigated whether the CVE confidence factor being inert on web-only scans was worth
fixing by reweighting. Tested **renormalization** and **CVE-or-CWE partial credit** on
the benchmark — **both rejected with evidence** (neither beat the binary baseline;
catalogue presence is not discriminating). The productive lever was the
data-completeness fixes above, not reweighting. Recorded in `WRITEUP_NOTES.md`.

### C. Verification

- Ran **live ZAP+Nuclei autoscans** against OWASP Juice Shop (no crashes; guardrails held).
- **Ingest-based pipeline test** proving both the CWE mapper and NVD back-fill fire end-to-end.
- **Live re-verified** the ML accuracy on the held-out set.

### D. Documentation

| Commit | What |
|---|---|
| `97c81e8`, `bc8bafa` | `WRITEUP_NOTES.md` — honest evaluation framings (FP handling, the reweighting negative result, CWE fixes, ML caveat) + updated ML training note. |
| `5a16d6c` | **Chapter 4: Design & Implementation** — full dissertation chapter (Markdown), OOAD, with 11 Mermaid diagrams and **8 real screenshots** captured from the running app. |
| `18eb3cc` | Fixed a Mermaid render error (semicolon in the activity diagram). |
| `63ad299` | **Word (.docx) build** of Chapter 4 — diagrams rasterised to PNG + `pandoc` conversion, 19 embedded images. |

## 8. Current status

- **90 tests passing** (`cd backend && python -m pytest`).
- Everything committed and pushed; `main` in sync with `origin`.
- Chapter 4 available as Markdown (`docs/CHAPTER_4_DESIGN_AND_IMPLEMENTATION.md`, renders
  on GitHub) and Word (`docs/Chapter_4_Design_and_Implementation.docx`).

## 9. Open backlog / ideas

- Nessus auto-launch (needs Nessus Manager / Tenable.io — Essentials blocks REST scan creation).
- More real labelled data for the confidence benchmark (biggest lever for a stronger evaluation claim).
- Minor: Nuclei parser mis-extracts the `method` field on some detections; the frontend bundle is one 768 KB chunk; web-mode has no seeded first-run user.
- Rotate the Nessus API keys pasted in chat earlier (now in git-ignored `.env`, unused).

## 10. Key file map

| Path | Purpose |
|---|---|
| `CLAUDE.md` | Authoritative design/instructions for the codebase. |
| `WRITEUP_NOTES.md` | Honest evaluation framings for the dissertation. |
| `docs/CHAPTER_4_DESIGN_AND_IMPLEMENTATION.md` | Chapter 4 (Markdown + Mermaid + screenshots). |
| `docs/Chapter_4_Design_and_Implementation.docx` | Word build of Chapter 4. |
| `docs/diagrams/`, `docs/images/` | Rendered diagrams and app screenshots. |
| `backend/app/engines/` | The triage pipeline engines. |
| `backend/app/ml/` | Random Forest training/inference. |
| `backend/cli.py` | Command-line entry point. |
