"""
CWE → typical-CVSS-vector profile builder.

Many web-scanner findings (notably OWASP ZAP) carry a CWE but NO CVSS vector, so
the ML severity model — which reasons over the 8 CVSS v3 sub-metrics — receives
an all-zero feature vector and predicts "Low" for everything. This builder mines
the NVD JSON feeds and records, for each CWE, the **modal (most common) value of
each CVSS sub-metric** across all CVEs of that weakness type. The result is a
small JSON lookup used by `cwe_cvss_enrichment` to fill a *plausible, empirically
grounded* vector onto vector-less findings before ML inference.

This is an approximation: "what does a typical CWE-79 vulnerability look like in
CVSS terms?" — derived from data, not hand-picked. Inferred vectors are flagged
so downstream consumers can treat them with appropriate caution.

Run:
  cd backend && python -m app.ml.cwe_profile_builder
Writes ml_data/cwe_cvss_profiles.json.
"""

import os
import sys
import json
import statistics
from collections import Counter, defaultdict
from datetime import datetime

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

import ijson
from app.ml.json_feed_processor import _open, _detect_array_key, list_json_feeds

# CVSS sub-metrics we profile, and the cvssData key each comes from.
_METRIC_KEYS = {
    "attack_vector": "attackVector",
    "attack_complexity": "attackComplexity",
    "privileges_required": "privilegesRequired",
    "user_interaction": "userInteraction",
    "scope": "scope",
    "confidentiality_impact": "confidentialityImpact",
    "integrity_impact": "integrityImpact",
    "availability_impact": "availabilityImpact",
}

# Abbreviations for building a CVSS vector string from the modal values.
_ABBR = {
    "attack_vector": ("AV", {"NETWORK": "N", "ADJACENT_NETWORK": "A", "ADJACENT": "A",
                             "LOCAL": "L", "PHYSICAL": "P"}),
    "attack_complexity": ("AC", {"LOW": "L", "HIGH": "H"}),
    "privileges_required": ("PR", {"NONE": "N", "LOW": "L", "HIGH": "H"}),
    "user_interaction": ("UI", {"NONE": "N", "REQUIRED": "R"}),
    "scope": ("S", {"UNCHANGED": "U", "CHANGED": "C"}),
    "confidentiality_impact": ("C", {"HIGH": "H", "LOW": "L", "NONE": "N"}),
    "integrity_impact": ("I", {"HIGH": "H", "LOW": "L", "NONE": "N"}),
    "availability_impact": ("A", {"HIGH": "H", "LOW": "L", "NONE": "N"}),
}

MIN_CWE_COUNT = 5  # below this, a CWE's profile is too sparse — fall back to global


def _cvss_v3(metrics: dict) -> dict | None:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData") or {}
            if data.get("baseScore") is not None:
                return data
    return None


def _first_cwe(weaknesses) -> int | None:
    for w in weaknesses or []:
        for desc in w.get("description", []):
            val = (desc.get("value") or "").strip()
            if val.startswith("CWE-") and val[4:].isdigit():
                return int(val[4:])
    return None


def _vector_string(metrics: dict) -> str:
    parts = ["CVSS:3.1"]
    for field, (tag, table) in _ABBR.items():
        parts.append(f"{tag}:{table.get(metrics[field], '?')}")
    return "/".join(parts)


def build_profiles(nvd_dir: str) -> dict:
    feeds = list_json_feeds(nvd_dir)
    if not feeds:
        raise ValueError(f"No JSON feeds in {nvd_dir}; run the feed download first.")

    counters = defaultdict(lambda: {m: Counter() for m in _METRIC_KEYS})
    scores = defaultdict(list)
    global_ctr = {m: Counter() for m in _METRIC_KEYS}
    global_scores = []
    total = 0

    for path in feeds:
        key = _detect_array_key(path)
        if not key:
            continue
        print(f"  [CWEProfile] scanning {os.path.basename(path)} ...", end=" ", flush=True)
        n = 0
        with _open(path) as fh:
            for item in ijson.items(fh, f"{key}.item"):
                cve = item.get("cve", item) if isinstance(item, dict) else None
                if not cve:
                    continue
                data = _cvss_v3(cve.get("metrics") or {})
                if not data:
                    continue
                vals = {}
                ok = True
                for m, src in _METRIC_KEYS.items():
                    v = data.get(src)
                    if not v:
                        ok = False
                        break
                    vals[m] = v.upper()
                if not ok:
                    continue
                score = float(data["baseScore"])
                cwe = _first_cwe(cve.get("weaknesses"))
                for m, v in vals.items():
                    global_ctr[m][v] += 1
                global_scores.append(score)
                if cwe is not None:
                    for m, v in vals.items():
                        counters[cwe][m][v] += 1
                    scores[cwe].append(score)
                n += 1
                total += 1
        print(f"{n:,} CVEs with full vectors")

    def modal_profile(ctr):
        return {m: ctr[m].most_common(1)[0][0] for m in _METRIC_KEYS}

    global_profile = modal_profile(global_ctr)
    global_profile["_vector"] = _vector_string(global_profile)
    global_profile["median_score"] = round(statistics.median(global_scores), 1)

    by_cwe = {}
    for cwe, ctr in counters.items():
        count = sum(ctr["attack_vector"].values())
        if count < MIN_CWE_COUNT:
            continue
        prof = modal_profile(ctr)
        prof["_vector"] = _vector_string(prof)
        prof["median_score"] = round(statistics.median(scores[cwe]), 1)
        prof["count"] = count
        by_cwe[str(cwe)] = prof

    return {
        "version": 1,
        "generated_at": datetime.utcnow().isoformat(),
        "source": f"NVD CVSS-v3 feeds, {total:,} CVEs with full vectors, "
                  f"{len(by_cwe)} CWEs profiled (min {MIN_CWE_COUNT} each)",
        "global": global_profile,
        "by_cwe": by_cwe,
    }


def main():
    nvd_dir = os.path.join(_BACKEND_DIR, "..", "ml_data", "nvd")
    out_path = os.path.join(_BACKEND_DIR, "..", "ml_data", "cwe_cvss_profiles.json")
    profiles = build_profiles(nvd_dir)
    with open(out_path, "w") as f:
        json.dump(profiles, f, indent=2)
    print(f"\n{profiles['source']}")
    print(f"Wrote {os.path.abspath(out_path)}")
    # Show a few familiar web CWEs.
    for cwe in ("79", "89", "22", "352", "1021"):
        p = profiles["by_cwe"].get(cwe)
        if p:
            print(f"  CWE-{cwe}: {p['_vector']}  (median CVSS {p['median_score']}, n={p['count']})")


if __name__ == "__main__":
    main()
