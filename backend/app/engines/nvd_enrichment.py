"""
NVD Enrichment Engine

Enriches NormalizedFindings with data from the National Vulnerability Database.
For findings that have a CVE ID, it fetches:
  - CVSS v3 base score and vector
  - Individual CVSS metric values (attack vector, complexity, etc.)
  - Exploit availability

Two modes:
  1. API mode  – live queries to api.nvd.nist.gov (requires NVD_API_KEY)
  2. Local mode – reads from pre-downloaded NVD JSON feed files in ml_data/nvd/
"""

import json
import os
import time
import requests
from flask import current_app
from app import db
from app.models.normalized_finding import NormalizedFinding
from app.utils.helpers import cvss_score_to_severity


class NvdEnrichmentEngine:
    # NVD API rate limit: 5 req/30s without key, 50 req/30s with key
    _RATE_LIMIT_DELAY = 0.7  # seconds between requests

    def enrich_finding(self, finding: NormalizedFinding) -> bool:
        """Enrich a single finding. Returns True if data was added."""
        if not finding.cve_id:
            return False
        if finding.nvd_enriched:
            return False

        cve_data = self._lookup_cve(finding.cve_id)
        if not cve_data:
            return False

        self._apply_cve_data(finding, cve_data)
        finding.nvd_enriched = True
        db.session.add(finding)
        return True

    def enrich_all_pending(self) -> int:
        """Enrich all findings with CVE IDs that haven't been enriched yet."""
        pending = NormalizedFinding.query.filter(
            NormalizedFinding.cve_id.isnot(None),
            NormalizedFinding.nvd_enriched.is_(False),
        ).all()

        enriched = 0
        for finding in pending:
            if self.enrich_finding(finding):
                enriched += 1
            time.sleep(self._RATE_LIMIT_DELAY)

        db.session.commit()
        return enriched

    def _lookup_cve(self, cve_id: str) -> dict | None:
        """Try local cache first, then NVD API."""
        local = self._lookup_local(cve_id)
        if local:
            return local
        return self._lookup_api(cve_id)

    def _lookup_local(self, cve_id: str) -> dict | None:
        """Search pre-downloaded NVD JSON feed files."""
        nvd_dir = os.path.join(
            current_app.root_path, "..", "ml_data", "nvd"
        )
        nvd_dir = os.path.normpath(nvd_dir)

        if not os.path.isdir(nvd_dir):
            return None

        for fname in os.listdir(nvd_dir):
            if not fname.endswith(".json"):
                continue
            try:
                with open(os.path.join(nvd_dir, fname), "r", encoding="utf-8") as f:
                    data = json.load(f)
                # Support both NVD feed format and API 2.0 format
                vulnerabilities = data.get("vulnerabilities") or data.get("CVE_Items") or []
                for item in vulnerabilities:
                    cve_block = item.get("cve", item)
                    item_id = (
                        cve_block.get("id")
                        or cve_block.get("CVE_data_meta", {}).get("ID", "")
                    )
                    if item_id.upper() == cve_id.upper():
                        return cve_block
            except (json.JSONDecodeError, OSError):
                continue
        return None

    def _lookup_api(self, cve_id: str) -> dict | None:
        api_key = current_app.config.get("NVD_API_KEY", "")
        base_url = current_app.config.get("NVD_BASE_URL")

        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        try:
            response = requests.get(
                base_url,
                params={"cveId": cve_id},
                headers=headers,
                timeout=10,
            )
            if response.status_code != 200:
                return None
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve")
        except requests.RequestException:
            pass
        return None

    @staticmethod
    def _apply_cve_data(finding: NormalizedFinding, cve: dict) -> None:
        """Write NVD CVE data fields onto the finding."""
        metrics = cve.get("metrics", {})

        # Prefer CVSS v3.1, fallback to v3.0
        cvss_v3 = (
            metrics.get("cvssMetricV31", [{}])[0].get("cvssData")
            or metrics.get("cvssMetricV30", [{}])[0].get("cvssData")
            or {}
        )

        score = cvss_v3.get("baseScore")
        if score is not None and finding.cvss_score is None:
            finding.cvss_score = float(score)
            finding.severity = cvss_score_to_severity(finding.cvss_score)

        finding.cvss_vector = cvss_v3.get("vectorString") or finding.cvss_vector
        finding.attack_vector = cvss_v3.get("attackVector")
        finding.attack_complexity = cvss_v3.get("attackComplexity")
        finding.privileges_required = cvss_v3.get("privilegesRequired")
        finding.user_interaction = cvss_v3.get("userInteraction")
        finding.scope = cvss_v3.get("scope")
        finding.confidentiality_impact = cvss_v3.get("confidentialityImpact")
        finding.integrity_impact = cvss_v3.get("integrityImpact")
        finding.availability_impact = cvss_v3.get("availabilityImpact")

        # Check for known exploits via CISA KEV data embedded in NVD feed
        cisa = cve.get("cisaExploitAdd")
        vuln_status = cve.get("vulnStatus", "")
        finding.exploit_available = bool(cisa) or "exploit" in vuln_status.lower()
