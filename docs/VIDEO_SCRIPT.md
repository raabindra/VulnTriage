# VulnTriage — Demo Video Script

**Presenter:** Raabindra (TP070723) · BSc (Hons) in Cyber Security
**Project:** VulnTriage — AI-Assisted Vulnerability Triage and Confirmation System Using ML and Multi-Scanner Analysis
**Target length:** ~7–8 minutes

> **How to use this script.** Each scene has **[SHOW]** (what to have on screen / do) and **[SAY]** (narration, first person). Record your screen with the app running, and read the SAY lines at a calm pace. Timings are guidance, not strict. Before recording, start the backend and frontend, log in once to warm it up, and have one scanner report ready to upload.

---

## Pre-recording checklist
- [ ] Backend running (Docker or Python 3.12 venv) and reachable
- [ ] Frontend running in the browser, zoomed so text is readable on video
- [ ] A demo account created; be logged out at the start
- [ ] A sample scanner report ready (e.g. the OWASP ZAP / Nuclei report from `samples/`)
- [ ] A local OWASP Juice Shop running if you will demo Auto Scan
- [ ] AI-assisted analysis key configured (optional, for the report scene)
- [ ] Screen recorder set to 1080p; microphone tested

---

## Scene 1 — Introduction (0:00–0:45)

**[SHOW]** Title slide or the app's login page.

**[SAY]**
"Hi, my name is Raabindra, and this is my final-year project, **VulnTriage** — an AI-assisted vulnerability triage and confirmation system.
When you run automated security scanners like OWASP ZAP, Nuclei, or Nessus, they produce a huge number of findings, and many of them are false positives or low-value noise. Verifying each one by hand is slow and repetitive — a problem known as *alert fatigue*.
VulnTriage solves this by automatically confirming, prioritising, and explaining scanner findings, so an analyst can focus only on the vulnerabilities that are actually real and important. Let me show you how it works."

---

## Scene 2 — The pipeline in one sentence (0:45–1:20)

**[SHOW]** Optionally a simple architecture/pipeline diagram slide, or just talk over the dashboard.

**[SAY]**
"Under the hood, every finding flows through a single automated pipeline: it is normalised, duplicates from different scanners are merged, it is mapped to a weakness type and enriched from the National Vulnerability Database, then a machine-learning model predicts its priority, a confidence engine scores how likely it is to be real, an optional Proof-of-Concept check actively tests it, and finally a professional report is generated. Let's walk through the system itself."

---

## Scene 3 — Authentication (1:20–1:45)

**[SHOW]** Register a new account (or log in). Reach the dashboard.

**[SAY]**
"The system is a secure web application. I'll log in here — authentication is handled with JSON Web Tokens, and every feature is gated behind a valid session. Once I'm in, I land on the dashboard."

---

## Scene 4 — Dashboard (1:45–2:45)

**[SHOW]** The dashboard: KPI cards, the severity / classification / scanner charts, and the top-vulnerabilities table.

**[SAY]**
"This is the dashboard — the analyst's overview. At the top are the key numbers: the total findings, how many are *Confirmed*, how many need manual verification, and how many scanner reports have been uploaded.
Below that, these charts summarise the dataset — the breakdown by severity, by classification, and by which scanner found what.
And here is a ranked table of the most severe vulnerabilities by CVSS score, so I can jump straight to what matters most. Notice how the system has already separated the confirmed vulnerabilities from the noise."

---

## Scene 5 — Ingesting findings: Upload (2:45–3:30)

**[SHOW]** Go to the Upload screen. Select a scanner type, drop in the sample report, toggle the pipeline options (Exploit search, PoC validation), and start the triage.

**[SAY]**
"There are two ways to get findings into the system. The first is to upload an existing scanner report — VulnTriage supports OWASP ZAP, Nuclei, and Nessus.
I'll select the scanner type and drop in my report. Before running, I can enable two optional steps: an exploit-database lookup, and active Proof-of-Concept validation, which actually tests whether the vulnerability is exploitable.
I'll start the triage pipeline now, and the system parses, de-duplicates, enriches, prioritises, and scores every finding automatically."

---

## Scene 6 — Auto Scan and responsible use (3:30–4:15)

**[SHOW]** Go to the Auto Scan screen. Enter the authorised target, select scanners, and point to the authorisation checkbox before starting.

**[SAY]**
"The second way is Auto Scan, where the system runs the scanners for me against a target. This is a deliberately-vulnerable practice application, OWASP Juice Shop, which I am authorised to test.
Notice this authorisation control — the scan will not start until I explicitly confirm I have permission to test the target. This is a core design principle of the project: active security testing must be responsible and authorised. I'll acknowledge it and start the scan."

---

## Scene 7 — Findings list (4:15–4:50)

**[SHOW]** The Findings screen. Use the search box and the severity / classification / scanner filters. Sort by confidence.

**[SAY]**
"All processed vulnerabilities appear here in the Findings list. It's fully searchable and filterable — I can filter by severity, by classification, or by the scanner that found it.
Each row shows the severity, CVSS score, CWE, the scanner, the confidence score, and the status. This lets me instantly narrow down to the high-priority, confirmed findings and ignore everything the system has already dismissed as noise."

---

## Scene 8 — The heart of the system: Finding Detail (4:50–6:15)

**[SHOW]** Open a Confirmed finding — ideally the SQL injection. Scroll through: description, CVSS metrics, CWE, ML prediction, the confidence score with its six-factor breakdown, the PoC evidence, and the AI analysis. Show the reclassify control.

**[SAY]**
"This is the most important screen in the whole system — the Finding Detail page — and it's where VulnTriage's core idea comes to life: **explainable, evidence-backed triage**.
For this SQL injection, you can see the full description, the CVSS metrics, and the mapped weakness, CWE-89.
Here is the machine-learning prediction of its priority. And here is the confidence score — 82 out of 100, classified *Confirmed*.
Crucially, the system doesn't just give a number — it shows *why*. This is the six-factor breakdown: scanner agreement, whether the ML severity is consistent, CVE and exploit availability, Proof-of-Concept validation, and CWE mapping. Each factor shows its contribution and a plain-language reason.
And this is the objective evidence: the Proof-of-Concept validator actively confirmed this vulnerability by sending a real payload that triggered a database error. So this isn't a guess — it's proven.
If I ever disagree, I can manually reclassify the finding here. This transparency is what lets an analyst *trust* the automated verdict."

---

## Scene 9 — AI-assisted analysis and reporting (6:15–7:00)

**[SHOW]** Trigger / show the AI-assisted analysis, then generate and open the PDF report (cover, executive summary, AI analysis, per-finding detail).

**[SAY]**
"On top of that, VulnTriage uses a large language model to generate an AI-assisted analysis — a plain-language summary of each vulnerability, its risk, and the recommended fix.
Finally, everything comes together in a professional PDF report. It has a cover page, an executive summary, the AI-written analysis, and the full per-finding detail with the confidence rationale — a document I can hand straight to a stakeholder."

---

## Scene 10 — Results and evidence (7:00–7:45)

**[SHOW]** A slide with the key results, or the evaluation output.

**[SAY]**
"To back this up with results: the machine-learning prioritiser achieves **99.68% accuracy** on over twenty-one thousand unseen records from the National Vulnerability Database.
The whole system was validated on a real scan of OWASP Juice Shop. Every finding the Proof-of-Concept validator confirmed — including that exploited SQL injection — was correctly classified *Confirmed*, while all the informational scanner noise was pushed down to *Informational*. A clean, real-world separation of signal from noise.
And the entire backend is backed by 96 automated tests, all passing."

---

## Scene 11 — Conclusion (7:45–8:15)

**[SHOW]** Title slide or dashboard again.

**[SAY]**
"In summary, VulnTriage shows that machine learning, multi-scanner corroboration, and active Proof-of-Concept validation can be combined into a single, explainable system that meaningfully reduces the manual effort and false-positive noise of vulnerability triage — while keeping every decision transparent and evidence-backed.
Thank you for watching."

---

## Delivery tips
- Speak a little slower than feels natural; pause between scenes.
- Move the mouse deliberately to whatever you're describing, so the viewer's eye follows.
- If a live action is slow (a scan or pipeline run), cut/trim the wait in editing, or say "I'll skip ahead while this runs."
- Keep each finding/screen on-screen for a beat after you finish talking, so viewers can read it.
- If the AI or a live scan is unreliable on the day, pre-run it and show the stored result instead.
