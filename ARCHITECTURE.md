# VulnTriage — AI-Assisted Vulnerability Triage System

Final-year project: ingests output from multiple web/infra scanners, normalises
and de-duplicates findings, enriches them (CWE + NVD), prioritises them with a
machine-learning model, scores confidence, optionally runs live non-destructive
PoC checks, and produces a PDF triage report.

## Stack
- **Backend:** Flask + SQLAlchemy 2.x (Flask-SQLAlchemy 3.x), JWT auth. Entry: `backend/run.py` (dev), `backend/wsgi.py` (gunicorn/prod).
- **Frontend:** React 18 + Vite + Tailwind (`frontend/`). API base is the relative path `/api`, so the backend can serve the built SPA same-origin.
- **DB:** PostgreSQL by default; **SQLite** for standalone/desktop/CLI use. Selected via the `DATABASE_URL` env var. Models use generic `db.JSON` (no Postgres-only column types), so SQLite is safe.
- **ML:** a **pure-NumPy Random Forest** (`backend/app/ml/random_forest.py`), pickled at `ml_data/models/random_forest.pkl`. Inference needs **only NumPy** — scikit-learn/pandas are training-only. `ml_data/models/` is git-ignored.
  - **Anti-leakage (important):** the model predicts the severity band from the **CVSS vector sub-metrics + CWE only — `cvss_score` is NOT a feature.** The label is derived from `cvss_score`, so feeding the score back in is target leakage and yields a meaningless ~100% accuracy. `FEATURE_COLUMNS` in `model_trainer.py` and `predictor.py` must stay identical (9 features, no score). Synthetic augmentation runs **only on the training split** (after a stratified split of the real data) so oversampled near-duplicates never cross into the test set; with the JSON feeds it is effectively a no-op (every class has thousands of real rows). Headline metric is **macro-F1**; evaluation is on **real held-out NVD rows only**.
  - **Training data:** prefers structured **NVD JSON 2.0 feeds** (`ml_data/nvd/CVE-YYYY.json[.xz]`, ~108k CVSS-v3 rows for 2023–25) via `json_feed_processor.py`, falling back to the Spanish `nvdtrans` XML (~800 regex-inferred rows) only when no JSON is present. Feeds are read straight from `.xz` with `ijson` (constant memory) — **the box is disk-full, never decompress feeds to disk.** Source: the `fkie-cad/nvd-json-data-feeds` GitHub release assets (the live NVD API is unreachable from here). Current JSON-trained model: acc ≈ 0.997, macro-F1 ≈ 0.994 on 21.7k real held-out rows; Critical-class F1 0.99.
  - **Honest caveat for the writeup:** CVSS v3.1 base score is a *deterministic* function of the 8 sub-metrics, so the model is essentially learning to reproduce the CVSS scoring function (errors only at band boundaries). High accuracy here is legitimate (no leakage) but reflects a near-deterministic task — the genuinely novel ML value lives in the Confidence Engine / triage, not this prioritiser. Predicting something CVSS *can't* give (e.g. EPSS exploitability) is the future-work lever. `data_processor.py` (older unused JSON path) still lists `cvss_score` — do not wire it into training without removing the score first.

## Scope note (optional orchestration)
The **core** of VulnTriage is a *triage* system over existing scanner output (it does not implement scanning). An **optional Auto Scan orchestration layer** can additionally *drive* the external tools (OWASP ZAP, Nuclei, Nessus) against a target and feed their native reports into the same pipeline — it shells out to / calls the real tools, it is not itself a scanner. Active scanning is intrusive and gated behind an explicit authorisation acknowledgement.

## Auto Scan (`engines/scanner_runner.py`, `engines/auto_scan.py`)
- **Runners (auto-launched): ZAP + Nuclei only** — Nuclei (`nuclei -u <t> -jsonl`), ZAP (headless `zaproxy -cmd -quickurl`). `SUPPORTED_SCANNERS = ("zap","nuclei")`; availability via `scanner_availability()`; per-scanner timeouts via env (`ZAP_TIMEOUT`/`NUCLEI_TIMEOUT`).
- **Nessus is NOT auto-launched:** Nessus Essentials/Professional block scan creation via the REST API (POST /scans resets). Use Nessus via the normal flow — export a `.nessus` report from the Nessus UI and upload it (the nessus parser + pipeline handle it like any other report).
- **Orchestrator** runs each scanner → ingests each native report via `parse_scanner_file` → runs the **unified** pipeline once across all uploads, so cross-scanner duplicates merge (↑ scanner_count → ↑ confidence). Requires `authorise=True`.
- **Surfaces:** CLI `python cli.py autoscan <target> -s zap,nuclei --authorise [--exploits] [--poc] [--scope ...]`; web `GET /api/pipeline/scanners` + `POST /api/pipeline/autoscan`; GUI "Auto Scan" page (`frontend/src/pages/AutoScan.jsx`) with target + scanner checkboxes + authorisation tick.

## Pipeline (the core engine, in `backend/app/engines/`)
`normalisation → deduplication (SHA-256 merge) → cwe_mapper → nvd_enrichment → cwe_cvss_enrichment → ml/predictor → confidence_engine → (optional) poc_validator → report_generator`
- **cwe_cvss_enrichment** (`engines/cwe_cvss_enrichment.py`): fills a *plausible, data-derived* CVSS v3 vector onto findings that have a CWE but no vector (typical of ZAP), so the ML severity model gets real features instead of all-zeros (which made it predict "Low" for everything). Only fills when `attack_vector` is unset (scanner/NVD vectors win) and flags `finding._vector_inferred` so the Confidence Engine notes provenance. The per-CWE modal vectors are mined from the NVD feeds by `python -m app.ml.cwe_profile_builder` → `ml_data/cwe_cvss_profiles.json` (425 CWEs; e.g. CWE-79→CVSS 6.1, CWE-89→7.6). Missing-profile findings fall back to the global modal vector; missing file → step is a no-op.
Orchestrated for the web app in `backend/app/routes/pipeline.py`; the CLI and desktop app reuse the same engines.

Confidence: 6-factor weighted score (0–100). ≥70 Confirmed, 40–69 Needs Manual Verification, <40 Not Confirmed. **PoC override:** any `poc_validation.result == "confirmed"` forces classification to "Confirmed" and score ≥75.
- **Confidence ≠ severity (important design choice):** the score estimates *likelihood the finding is a true positive*, not how damaging it is. Every factor is a **reliability** signal. Factors + documented weights: scanner_agreement 25, severity_consistency 20 (does ML priority *agree* with scanner severity — the ML model's contribution to confidence via agreement, neutral when the scanner gives no CVSS vector), cve_availability 15, exploit_availability 15, poc_validation 15, cwe_mapping 10. The earlier `ml_priority` *magnitude* factor was removed (it conflated severity with confidence); its DB column `ml_priority_score` is repurposed to store `severity_consistency`.
- **Explainability:** `factor_breakdown` is v2 — `{version, factors:{k:{raw_score,weight,contribution,reason}}, rationale}`. The per-factor `reason` and one-paragraph `rationale` are rendered in the PDF report ("Why this classification") and the Finding detail page. `ConfidenceEngine.compute_score(finding)` is a **pure** function (no DB writes) used by both `score_finding` and the eval harness; it duck-types the finding, so stand-ins work.
- **Evaluation:** `python -m scripts.evaluate_confidence` scores a **curated synthetic benchmark** (`app/engines/eval/labelled_findings.py` — includes deliberate hard/overlapping cases so it is NOT trivially separable; report it as a curated benchmark, not field-validated). Current: ROC-AUC ≈ 0.82, "Confirmed" precision 1.0 / recall 0.38, ~81% FP suppression at 75% TP retention, AUC stable 0.81–0.83 across weightings. Writes `reports_output/confidence_eval.{md,json}`.

## Three ways to run (see DEPLOYMENT.md for full steps)
- **Desktop app (Kali, native window):** `./install-kali-app.sh` then launch "VulnTriage" from the menu, or `python backend/desktop_app.py`. Uses pywebview (GTK/WebKit) + waitress + SQLite at `~/.local/share/vulntriage/`. Login: `admin / admin`.
- **Docker Compose (web app):** `docker compose up --build` → http://localhost:5000. Pins **Python 3.12** in-container (the pinned numpy/sklearn/pandas lack 3.14 wheels).
- **CLI:** `python backend/cli.py scan <file> -s <zap|nuclei|nessus> [--poc] [--scope host1,host2] [--exploits] [-o out.pdf]`. Defaults to `./vulntriage.db` SQLite.

## PoC validation & exploit lookup (`engines/poc_validator.py`, `engines/exploit_search.py`)
- **Active PoC checks (non-destructive):** XSS reflection, SQLi (error + boolean + **time-based blind** SLEEP), **open redirect** (CWE-601), **path traversal/LFI** (CWE-22/98, read-only `/etc/passwd` signature), security-header, CORS, generic reflection, version disclosure. Supports **GET and POST** (honours `finding.method`; `_fetch` puts the payload in the query string or form body). A `confirmed` PoC hard-overrides the Confidence Engine classification.
- **Authorisation scope (responsible-tooling guard):** `PocValidator(scope=...)` / `--scope` / `POC_SCOPE` env (comma-separated hosts). When set, probes to out-of-scope hosts are `skipped` with no network call (matches host or subdomain). **Empty scope = unrestricted (legacy)** — operators should set it. Payloads are read-only/time-based only (no writes/drops).
- **Exploit lookup:** `--exploits` / `search_exploits` runs `searchsploit -j` (Exploit-DB) per finding — exact `--cve` lookup, else title keywords — sets `exploit_available` (feeds the confidence factor) and appends `EDB-<id>` refs to `finding.reference`. Degrades to a no-op if `searchsploit` is absent.

A ready-to-use sample report is at `samples/zap-sample.xml`.

## Local dev (without Docker)
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate   # add --system-site-packages for the desktop app
pip install -r requirements.txt                       # + -r requirements-desktop.txt for the desktop app
# backend:  python run.py            (needs DATABASE_URL or a running Postgres)
# frontend: cd ../frontend && npm install && npm run dev   (Vite on :3000, proxies /api to :5000)
```

## Tests
`cd backend && python -m pytest` — no Postgres needed. Tests use the `testing` config (`config.py:TestingConfig`: in-memory SQLite on a `StaticPool`, bound at `create_app("testing")` so the engine never points at Postgres). Shared fixtures (`app`, `client`, `db`, `upload`) live in `tests/conftest.py` — **do not** re-declare an `app` fixture in a test module or return a tuple from it (`pytest-flask`'s autouse request-context fixture calls methods on the `app` value). Confidence Engine tests use the pure `compute_score()` and need no DB.

## Conventions & gotchas
- The codebase uses `datetime.utcnow()` throughout (Python 3.14 flags it as deprecated; the CLI silences that warning for clean output). Match the existing style.
- SQLAlchemy 2.0 `select()` style is required for reliable joins after PoC session operations — see `report_generator._load_findings`.
- **Deduplication + report scoping:** dedup merges re-uploaded findings into the *first* upload's records, so per-upload report scoping can return 0; `_load_findings` falls back to all-user findings. This is expected.
- `app/__init__.py` `create_app` serves the compiled SPA only when `FRONTEND_DIST` is set (Docker/desktop); local dev is unaffected. CORS origins come from `CORS_ORIGINS`.
- Verify previewable changes by actually running the relevant mode; don't just assume.
