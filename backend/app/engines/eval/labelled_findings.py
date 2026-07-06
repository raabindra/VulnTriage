"""
Labelled benchmark for evaluating the Confidence Engine.

⚠️  PROVENANCE / HONESTY NOTE
-----------------------------
This is a **curated, synthetic benchmark**, NOT real-world labelled scan data.
Each case is a hand-built scenario representative of patterns seen in real
multi-scanner triage (e.g. corroborated PoC-confirmed SQLi = true positive;
a lone "missing security header" with no corroboration = typical false
positive). The ground-truth `is_true_positive` label encodes "is this finding
a genuine, exploitable issue an analyst should act on?".

It exists to demonstrate that the engine's confidence score *separates* true
positives from false positives and to support a weight sensitivity analysis.
Headline numbers from it should always be reported as "on a curated benchmark
of N scenarios", never as field-validated accuracy. Replacing this with labels
from real Juice Shop / DVWA scans is the natural next step.

Stand-in objects duck-type the subset of `NormalizedFinding` that the engine
reads, so `ConfidenceEngine.compute_score` runs on them unchanged.
"""

from dataclasses import dataclass, field


@dataclass
class _MLPred:
    predicted_priority: str | None = None


@dataclass
class _PoC:
    result: str  # "confirmed" | "not_confirmed" | "error"
    # A strong, vuln-specific type by default so a "confirmed" benchmark PoC
    # exercises the hard-override (see ConfidenceEngine.STRONG_POC_TYPES).
    validation_type: str = "sqli_check"


@dataclass
class _PoCManager:
    """Mimics finding.poc_validations (a dynamic relationship with .all())."""
    items: list = field(default_factory=list)

    def all(self):
        return self.items


@dataclass
class _Vuln:
    raw_data: dict = field(default_factory=dict)


@dataclass
class FindingStub:
    title: str
    is_true_positive: bool
    severity: str = "Medium"
    scanner_count: int = 1
    scanner_sources: list = field(default_factory=list)
    cve_id: str | None = None
    cwe_id: str | None = None
    attack_vector: str | None = None          # presence => CVSS vector available
    exploit_available: bool = False
    _ml_priority: str | None = None
    _poc_results: list = field(default_factory=list)
    _poc_type: str = "sqli_check"      # strong by default; set weak to test override
    _raw_exploit: str | None = None

    # --- duck-typed accessors the engine expects -------------------------
    @property
    def ml_prediction(self):
        return _MLPred(self._ml_priority) if self._ml_priority else None

    @property
    def poc_validations(self):
        return _PoCManager([_PoC(r, self._poc_type) for r in self._poc_results])

    @property
    def source_vulnerability(self):
        if self._raw_exploit is not None:
            return _Vuln({"exploit_available": self._raw_exploit})
        return None

    # engine never reads these on a stub, but keep the attribute surface sane
    confidence_score = None
    classification = None
    id = None


def _tp(title, **kw):
    return FindingStub(title=title, is_true_positive=True, **kw)


def _fp(title, **kw):
    return FindingStub(title=title, is_true_positive=False, **kw)


def build_benchmark() -> list[FindingStub]:
    """Return the curated labelled benchmark."""
    return [
        # ---------------- TRUE POSITIVES ----------------
        _tp("SQL Injection (PoC-confirmed, 2 scanners)",
            severity="High", scanner_count=2, scanner_sources=["zap", "nuclei"],
            cwe_id="CWE-89", _ml_priority="High", attack_vector="NETWORK",
            _poc_results=["confirmed"]),
        _tp("Remote Code Execution via known CVE + public exploit",
            severity="Critical", scanner_count=2, scanner_sources=["nessus", "nuclei"],
            cve_id="CVE-2024-1709", cwe_id="CWE-94", exploit_available=True,
            attack_vector="NETWORK", _ml_priority="Critical"),
        _tp("Reflected XSS confirmed by controlled PoC",
            severity="Medium", scanner_count=1, scanner_sources=["zap"],
            cwe_id="CWE-79", _ml_priority="Medium", _poc_results=["confirmed"]),
        _tp("Path Traversal, corroborated, exploit available",
            severity="High", scanner_count=2, scanner_sources=["zap", "nuclei"],
            cwe_id="CWE-22", exploit_available=True, attack_vector="NETWORK",
            _ml_priority="High"),
        _tp("Authentication bypass with CVE + exploit (Nessus)",
            severity="Critical", scanner_count=1, scanner_sources=["nessus"],
            cve_id="CVE-2023-46805", cwe_id="CWE-287", _raw_exploit="true",
            attack_vector="NETWORK", _ml_priority="Critical"),
        _tp("SSRF confirmed by PoC, single scanner",
            severity="High", scanner_count=1, scanner_sources=["nuclei"],
            cwe_id="CWE-918", _ml_priority="High", attack_vector="NETWORK",
            _poc_results=["confirmed"]),
        _tp("Known CVE, exploit available, ML severity consistent",
            severity="High", scanner_count=1, scanner_sources=["nessus"],
            cve_id="CVE-2024-3400", cwe_id="CWE-77", exploit_available=True,
            attack_vector="NETWORK", _ml_priority="High"),
        _tp("Deserialization RCE, 3 scanners agree",
            severity="Critical", scanner_count=3, scanner_sources=["zap", "nuclei", "nessus"],
            cwe_id="CWE-502", attack_vector="NETWORK", _ml_priority="Critical"),
        _tp("Command injection, CVE + PoC confirmed",
            severity="Critical", scanner_count=2, scanner_sources=["nuclei", "nessus"],
            cve_id="CVE-2024-4577", cwe_id="CWE-78", exploit_available=True,
            attack_vector="NETWORK", _ml_priority="Critical", _poc_results=["confirmed"]),
        _tp("XXE corroborated by two scanners",
            severity="High", scanner_count=2, scanner_sources=["zap", "nuclei"],
            cwe_id="CWE-611", attack_vector="NETWORK", _ml_priority="High"),
        _tp("Open redirect confirmed by PoC",
            severity="Medium", scanner_count=1, scanner_sources=["zap"],
            cwe_id="CWE-601", _ml_priority="Low", _poc_results=["confirmed"]),
        _tp("Sensitive data exposure, CVE mapped, exploit available",
            severity="High", scanner_count=1, scanner_sources=["nessus"],
            cve_id="CVE-2023-34362", cwe_id="CWE-200", exploit_available=True,
            attack_vector="NETWORK", _ml_priority="High"),

        # ---------------- FALSE POSITIVES ----------------
        _fp("Missing X-Frame-Options header (lone, informational)",
            severity="Low", scanner_count=1, scanner_sources=["zap"],
            cwe_id="CWE-1021", _ml_priority="Low"),
        _fp("Server version disclosure (banner) — single scanner",
            severity="Low", scanner_count=1, scanner_sources=["zap"],
            cwe_id="CWE-200", _ml_priority="Low"),
        _fp("Reflected param flagged XSS but PoC NOT confirmed (sanitised)",
            severity="Medium", scanner_count=1, scanner_sources=["zap"],
            cwe_id="CWE-79", _ml_priority="Low", _poc_results=["not_confirmed"]),
        _fp("Possible SQLi (version-based heuristic), PoC failed",
            severity="High", scanner_count=1, scanner_sources=["nuclei"],
            cwe_id="CWE-89", _ml_priority="Low", _poc_results=["not_confirmed"]),
        _fp("Cookie without Secure flag (lone, low signal)",
            severity="Low", scanner_count=1, scanner_sources=["zap"],
            cwe_id="CWE-614", _ml_priority="Low"),
        _fp("Autocomplete enabled on form field",
            severity="Low", scanner_count=1, scanner_sources=["zap"],
            _ml_priority="Low"),
        _fp("Outdated jQuery flagged, no exploit, single scanner",
            severity="Medium", scanner_count=1, scanner_sources=["zap"],
            cwe_id="CWE-1104", _ml_priority="Low"),
        _fp("CSP not enforced (informational header check)",
            severity="Low", scanner_count=1, scanner_sources=["zap"],
            _ml_priority="Low"),
        _fp("Directory listing 'possible' (false trigger), PoC not confirmed",
            severity="Medium", scanner_count=1, scanner_sources=["nuclei"],
            cwe_id="CWE-548", _ml_priority="Low", _poc_results=["not_confirmed"]),
        _fp("Generic 'application error disclosure' (single, noisy)",
            severity="Low", scanner_count=1, scanner_sources=["zap"],
            cwe_id="CWE-200", _ml_priority="Low"),
        _fp("Cacheable HTTPS response (informational)",
            severity="Low", scanner_count=1, scanner_sources=["zap"],
            _ml_priority="Low"),
        _fp("Cross-domain misconfig 'potential' — unverified, lone",
            severity="Medium", scanner_count=1, scanner_sources=["zap"],
            cwe_id="CWE-942", _ml_priority="Low"),

        # ---------------- HARD CASES (deliberate overlap) ----------------
        # These exist so the benchmark is NOT trivially separable. Without them
        # the engine scores a perfect AUC, which would be a meaningless artifact
        # of cherry-picked easy examples. Real triage has weak-signal true
        # positives and strong-looking false positives; the engine SHOULD lose
        # some recall/precision here, and that honest cost is the point.

        # Hard TRUE POSITIVES — genuine issues with little corroboration.
        # The engine will under-score these (low scanner agreement, no CVE/PoC);
        # they expose the limit of a corroboration-based confidence model.
        _tp("Stored XSS, single scanner, no PoC run, no CVE",
            severity="High", scanner_count=1, scanner_sources=["zap"],
            cwe_id="CWE-79", _ml_priority="Low"),
        _tp("IDOR (real), single scanner, low scanner signal, no automated PoC",
            severity="Medium", scanner_count=1, scanner_sources=["zap"],
            cwe_id="CWE-639", _ml_priority="Low"),
        _tp("Business-logic auth flaw — lone scanner, unmapped",
            severity="High", scanner_count=1, scanner_sources=["zap"],
            _ml_priority="Low"),
        _tp("Real SQLi but automated PoC errored (timeout)",
            severity="High", scanner_count=1, scanner_sources=["nuclei"],
            cwe_id="CWE-89", _ml_priority="Low", _poc_results=["error"]),

        # Hard FALSE POSITIVES — strong-looking signals but actually false.
        _fp("Two scanners both flag 'missing header' that is actually present",
            severity="Medium", scanner_count=2, scanner_sources=["zap", "nuclei"],
            cwe_id="CWE-693", _ml_priority="Low"),
        _fp("Version-based CVE match, host actually patched (exploit exists for CVE)",
            severity="High", scanner_count=1, scanner_sources=["nessus"],
            cve_id="CVE-2021-44228", cwe_id="CWE-502", exploit_available=True,
            attack_vector="NETWORK", _ml_priority="High"),
        _fp("Mis-attributed CVE on a generic finding, single scanner",
            severity="Medium", scanner_count=1, scanner_sources=["nuclei"],
            cve_id="CVE-2019-0001", cwe_id="CWE-200", _ml_priority="Low"),
        _fp("CVE+CWE present but controlled PoC explicitly not confirmed",
            severity="High", scanner_count=1, scanner_sources=["nessus"],
            cve_id="CVE-2022-1388", cwe_id="CWE-306", attack_vector="NETWORK",
            _ml_priority="High", _poc_results=["not_confirmed"]),
    ]
