# User Acceptance Testing (UAT) Form

**VulnTriage — AI-Assisted Vulnerability Triage and Confirmation System**

> **Purpose.** Thank you for helping evaluate VulnTriage. Please complete the six tasks in Section B using the system, then rate your experience in Sections C–F and add any comments in Section G. There are no right or wrong answers — your honest opinion is what matters.
>
> **Authorisation & scope.** Any scanning during this test is performed **only** against the provided, deliberately-vulnerable practice target (e.g. a local OWASP Juice Shop). Do not point the system at any system you are not explicitly authorised to test.

---

## Section A — Tester Profile

| Field | |
|-------|--|
| Name | ____________________________ |
| Age | ____________ |
| Date | ____________ |
| Role | ____________________________ |
| Background | ☐ Cybersecurity student  ☐ Junior security analyst  ☐ IT / security staff  ☐ Other: __________ |
| Security-tool experience | ☐ None  ☐ Some  ☐ Experienced |

## Section B — Tasks (tick when completed)

| # | Task | Completed | Needed help? |
|---|------|:---------:|:------------:|
| 1 | Register an account and log in. | ☐ | Yes ☐ No ☐ |
| 2 | Upload a scanner report and run the triage pipeline. | ☐ | Yes ☐ No ☐ |
| 3 | From the dashboard, state how many findings are Confirmed vs the total. | ☐ | Yes ☐ No ☐ |
| 4 | Open a Confirmed finding and explain, in your own words, why it was confirmed. | ☐ | Yes ☐ No ☐ |
| 5 | Run an Auto Scan against the authorised target (acknowledging the authorisation control). | ☐ | Yes ☐ No ☐ |
| 6 | Generate and download the PDF report (including the AI-assisted analysis). | ☐ | Yes ☐ No ☐ |

## Section C — User Interface (rate 1–5)

*Scale: 1 = Strongly disagree · 2 = Disagree · 3 = Neutral · 4 = Agree · 5 = Strongly agree*

| Criterion | 1 | 2 | 3 | 4 | 5 |
|-----------|:-:|:-:|:-:|:-:|:-:|
| I. The dashboard layout is clear and well-organised. | ☐ | ☐ | ☐ | ☐ | ☐ |
| II. The colour-coded severity indicators are easy to interpret. | ☐ | ☐ | ☐ | ☐ | ☐ |
| III. Navigation between Upload, Findings, and Reports is intuitive. | ☐ | ☐ | ☐ | ☐ | ☐ |
| IV. The charts and KPI cards present the triage summary clearly. | ☐ | ☐ | ☐ | ☐ | ☐ |
| V. The finding-detail view is readable and well-structured. | ☐ | ☐ | ☐ | ☐ | ☐ |
| VI. Buttons, forms, and controls are obvious and easy to use. | ☐ | ☐ | ☐ | ☐ | ☐ |
| VII. The overall look and feel is professional. | ☐ | ☐ | ☐ | ☐ | ☐ |

## Section D — General Functionality (Yes / No)

| Criterion | Yes | No |
|-----------|:---:|:--:|
| I. The system registers a new account and logs in without error. | ☐ | ☐ |
| II. A scanner report (ZAP / Nuclei / Nessus) can be uploaded and processed without error. | ☐ | ☐ |
| III. Findings are triaged and classified automatically after upload. | ☐ | ☐ |
| IV. The system responds appropriately to invalid input or an unsupported file. | ☐ | ☐ |
| V. The PDF report generates and downloads successfully. | ☐ | ☐ |

## Section E — Triage / Analyst Functionality (Yes / No)

| Criterion | Yes | No |
|-----------|:---:|:--:|
| I. The confidence score and rationale help me judge whether a finding is real. | ☐ | ☐ |
| II. The Confirmed / Needs-Verification / Not-Confirmed classification is clear and useful. | ☐ | ☐ |
| III. The AI-assisted analysis (risk explanation and suggested fix) helps me understand the vulnerability. | ☐ | ☐ |
| IV. Deduplication correctly merges the same finding reported by multiple scanners. | ☐ | ☐ |
| V. The Auto Scan authorisation control makes the scope and consent clear. | ☐ | ☐ |
| VI. The generated report is suitable to hand to a stakeholder. | ☐ | ☐ |
| VII. Overall, the system reduces the manual effort of triaging scanner output. | ☐ | ☐ |

## Section F — Overall Acceptance

| Statement | Yes | No |
|-----------|:---:|:--:|
| I accept this system as usable and fit for its purpose. | ☐ | ☐ |
| I would recommend this system to others who triage scanner output. | ☐ | ☐ |

## Section G — Comments & Suggestions

________________________________________________________________

________________________________________________________________

________________________________________________________________

<br>

**Tester's signature:** __________________  **Date:** __________  **Facilitator:** __________________

*VulnTriage UAT Form · one form per tester · minimum three testers from the target audience*
