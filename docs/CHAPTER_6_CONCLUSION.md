# CHAPTER 6: CONCLUSION

This chapter concludes the project. It critically evaluates what VulnTriage set out to do and what it actually delivered, justifies the contribution the system makes to the security community and industry, and states the project's strengths plainly (§6.1). It then discusses the honest limitations of the work (§6.2), and finally offers concrete recommendations for future improvement (§6.3).

---

## 6.1 Critical Evaluation

### 6.1.1 Overall Achievement

The aim of this project was to reduce the manual burden and the false-positive noise that make triaging the output of automated vulnerability scanners slow and error-prone, by building a system that automatically **confirms, prioritises, and explains** scanner findings. Measured against its objectives, the project has been fully realised, and in several respects it went further than the minimum required.

Each of the project objectives was met, as summarised below:

- **Multi-scanner ingestion and normalisation.** VulnTriage ingests reports from three industry scanners — OWASP ZAP, Nuclei, and Nessus — parses their differing formats into a single normalised finding model, and merges duplicate findings reported by more than one tool using a deterministic SHA-256 group hash. This directly delivers the "multi-scanner analysis" objective and is verified by the parser and deduplication tests.
- **Machine-learning prioritisation.** A pure-NumPy Random Forest classifier predicts a severity/priority band for each finding from its CVSS sub-metrics and CWE, deliberately excluding the raw CVSS score to avoid label leakage. On **21,697 unseen, real NVD records** it achieved **99.68% accuracy and a macro-averaged F1 of 0.9941**, with every error only ever one severity band away from the truth — never a gross misclassification.
- **Confidence scoring and false-positive reduction.** A transparent six-factor Confidence Engine (scanner agreement, severity consistency, CVE availability, exploit availability, PoC validation, and CWE mapping) produces a 0–100 confidence score and a *Confirmed / Needs Manual Verification / Not Confirmed* classification. On a **real scan of OWASP Juice Shop**, it placed all five objectively PoC-confirmed findings in the *Confirmed* band and demoted every technology-detection noise item to *Informational* — a clean, real-world separation of signal from noise.
- **Proof-of-Concept validation.** A safety-bounded PoC validator actively probes candidate findings against the target within an explicit authorised scope. In testing it confirmed a genuine SQL injection in Juice Shop by exploitation (the payload `1'--` returned an HTTP 500 SQL error), demonstrating *confirmation by evidence* rather than by heuristic alone.
- **AI-assisted vulnerability analysis.** An LLM engine (Google Gemini) generates a plain-language executive summary, per-finding risk explanations, suggested fixes, and prioritised actions, which are embedded in the report to give the analyst a clearer picture of each vulnerability.
- **Professional report generation.** The system produces a complete, downloadable PDF report — cover, executive summary, AI-assisted analysis, and per-finding detail with the full confidence rationale — suitable to hand to a stakeholder.

Beyond these core objectives, the system was delivered as a complete, authenticated application with **three deployment modes** (a native desktop app, a Docker-based web application, and a command-line interface), all reusing the same engines, and it is backed by a deterministic automated test suite of **96 passing unit and integration tests** covering every component. Together these achievements show that the project not only accomplished its aim but produced a robust, end-to-end, usable system.

### 6.1.2 Contribution to the Community and Industry

VulnTriage addresses a real and widely-felt problem in application security: **alert fatigue**. Modern scanners generate large volumes of findings, many of which are false positives or informational noise, and analysts spend a disproportionate amount of time separating the few genuine, actionable vulnerabilities from the rest. By automating confirmation and prioritisation, the project makes a tangible contribution to that workflow.

The specific contributions are:

- **An explainable, evidence-backed triage verdict.** Rather than presenting a single opaque score, VulnTriage combines multi-scanner corroboration, machine-learning prioritisation, and *active* Proof-of-Concept confirmation into one confidence verdict, and — crucially — shows the full six-factor breakdown and a plain-language rationale behind it. This explainability lets an analyst *trust or challenge* the automated decision, which is essential for adoption in a security context where accountability matters.
- **A practical reduction of manual effort.** By auto-dismissing low-confidence noise and surfacing confirmed, high-priority findings first, the system shrinks the analyst's review set to the findings that actually matter, directly targeting the industry pain point of wasted triage time.
- **Reproducibility and offline capability.** The system enriches findings from local NVD feeds and runs its full test suite deterministically with no external dependencies, making it usable in air-gapped, budget-constrained, or educational environments where cloud services are unavailable.
- **Educational value.** For students and junior analysts learning the triage process, the transparent factor breakdown and evidence trail serve as a teaching aid that makes *why* a finding is or is not a real vulnerability concrete and inspectable.
- **A model of responsible security tooling.** Active scanning and PoC validation are gated behind an explicit authorisation acknowledgement and an in-scope host guard, demonstrating an ethical, authorised-use-only design that the security community increasingly expects of offensive-capable tools.

### 6.1.3 Strengths of the Project

The principal strengths of VulnTriage are:

- **Explainable and evidence-backed.** Every classification is accompanied by a per-factor breakdown, a rationale, and — where available — active PoC evidence, so no verdict is a black box.
- **Confirmation by evidence, not assumption.** The PoC validator actively verifies vulnerabilities against the live target, giving the *Confirmed* label objective grounding rather than relying only on scanner heuristics.
- **Strong, honestly-evaluated machine learning.** The prioritiser generalises with 99.68% accuracy on real, unseen NVD data, evaluated on a proper held-out split with anti-leakage feature selection.
- **Robust engineering.** A deterministic 96-test suite covering all fourteen components, three deployment modes sharing one engine core, and graceful degradation (e.g. the report still generates if the AI provider is unavailable) make the system dependable.
- **Responsible by design.** Authorisation gating and scope enforcement are built into the interface and the validator, not bolted on.

---

## 6.2 Limitation

While the project achieved its objectives, several limitations are acknowledged honestly:

- **Field validation of the confidence engine is limited.** The engine was validated on a real scan of a single deliberately-vulnerable target (OWASP Juice Shop), which demonstrates its *prioritisation* of genuine findings above noise but, because a single clean scan contains few outright scanner false positives, does not measure false-positive *suppression* in isolation across diverse, production-scale environments. A large, labelled, real-world dataset would be needed to establish that property conclusively.
- **The machine-learning task is close to deterministic.** The prioritiser predicts a severity band from CVSS sub-metrics and CWE, which are strongly correlated with the target; its very high accuracy therefore partly reflects the structured nature of the task rather than the harder problem of predicting real-world exploitability directly.
- **Proof-of-Concept coverage is partial.** The validator covers a defined subset of vulnerability classes (for example SQL injection, cross-site scripting, security-header issues, open redirect, path traversal, and CORS misconfiguration). Vulnerability types outside this set are triaged by the other factors but are not actively confirmed.
- **Scanner and standard coverage is bounded.** Ingestion is limited to OWASP ZAP, Nuclei, and Nessus, and enrichment currently targets CVSS v3; other scanners and CVSS v4 are not yet supported.
- **Dependence on external AI services.** The AI-assisted analysis relies on an external LLM provider (Google Gemini); it is optional and key-gated, and its availability, latency, and cost are outside the system's control (the system degrades gracefully without it).
- **User Acceptance Testing scale.** UAT is designed for, and conducted with, a small number of target-audience testers against a single practice target; it establishes acceptability rather than statistically-powered usability at enterprise scale.
- **Operational scale.** The system was developed and evaluated at project scale; performance, multi-tenant isolation, and fine-grained role-based access control under heavy real-world load were not a focus of this work.

---

## 6.3 Recommendation

The following recommendations are proposed for future improvement, building on the foundation this project established:

- **Broaden Proof-of-Concept coverage.** Add safe, well-bounded confirmation modules for further vulnerability classes (for example SSRF, XXE, deserialisation, and authentication bypass) so that more findings can be confirmed by evidence rather than by heuristic.
- **Field-validate and learn the confidence model.** Collect a large, labelled dataset from real engagements across diverse targets to validate false-positive suppression conclusively, and evolve the fixed weighted heuristic into a *learned* confidence model that improves from analyst feedback over time.
- **Integrate additional scanners and standards.** Extend ingestion to further tools (for example Burp Suite, Trivy, and Semgrep) and add support for CVSS v4, widening the system's applicability.
- **Add workflow and ecosystem integration.** Support scheduled/continuous scanning and push confirmed findings into ticketing and vulnerability-management platforms (for example Jira and DefectDojo) so the tool fits directly into an existing security operations workflow.
- **Offer a local/offline AI option.** Provide an on-premises or local-LLM alternative for the AI-assisted analysis to remove the external dependency and enable use in air-gapped environments.
- **Conduct a larger, longitudinal usability study.** Run UAT with a larger and more varied group of analysts over a sustained period in a realistic setting to gather statistically meaningful usability and adoption evidence.
- **Harden for production scale.** Add role-based access control, multi-tenant isolation, and performance optimisation so the system can be deployed dependably in a busy, multi-analyst security team.

In conclusion, VulnTriage successfully demonstrates that machine learning, multi-scanner corroboration, and active Proof-of-Concept validation can be combined into a single, explainable, evidence-backed triage system that meaningfully reduces the manual effort and false-positive noise of vulnerability triage. The project met all of its objectives, contributes a practical and ethically-designed tool to the security community, and — through the limitations and recommendations set out above — establishes a clear path for future work.
