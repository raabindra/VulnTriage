"""
Scanner runner — optional orchestration layer (Auto Scan).

VulnTriage's core remains a *triage* system over existing scanner output; this
module lets the app optionally DRIVE those external scanners against a target and
collect their native reports, which then feed the normal ingest+triage pipeline.
It does not implement any scanning itself — it shells out to / calls the real
tools (OWASP ZAP, Nuclei, Nessus).

⚠️  Active scanning is intrusive. Only run against assets you are authorised to
test. The orchestrator enforces an authorisation acknowledgement / scope.

Each adapter returns the path to a native report file the existing parsers can
read (ZAP XML, Nuclei JSONL, Nessus .nessus XML), or raises ScannerError.
"""

import os
import time
import shutil
import subprocess

import requests

# Tool locations (allow override via env for non-standard installs).
ZAP_BIN = os.environ.get("ZAP_BIN") or shutil.which("zaproxy") or shutil.which("zap.sh")
NUCLEI_BIN = os.environ.get("NUCLEI_BIN") or shutil.which("nuclei") \
    or os.path.expanduser("~/go-workspace/bin/nuclei")

# Default per-scanner wall-clock limits (seconds); override via env.
ZAP_TIMEOUT = int(os.environ.get("ZAP_TIMEOUT", "900"))
NUCLEI_TIMEOUT = int(os.environ.get("NUCLEI_TIMEOUT", "600"))
NESSUS_TIMEOUT = int(os.environ.get("NESSUS_TIMEOUT", "3600"))


class ScannerError(RuntimeError):
    pass


# ───────────────────────── availability ─────────────────────────
def _nuclei_ok() -> bool:
    return bool(NUCLEI_BIN and os.path.exists(NUCLEI_BIN))


def _zap_ok() -> bool:
    return bool(ZAP_BIN and os.path.exists(ZAP_BIN))


def _nessus_creds() -> tuple[str, str, str] | None:
    url = os.environ.get("NESSUS_URL", "https://localhost:8834")
    ak = os.environ.get("NESSUS_ACCESS_KEY")
    sk = os.environ.get("NESSUS_SECRET_KEY")
    if ak and sk:
        return url, ak, sk
    return None


def scanner_availability() -> dict:
    """Report which scanners can actually run right now."""
    return {
        "nuclei": {"available": _nuclei_ok(), "reason": "" if _nuclei_ok() else "nuclei binary not found"},
        "zap": {"available": _zap_ok(), "reason": "" if _zap_ok() else "zaproxy/zap.sh not found"},
        "nessus": {
            "available": _nessus_creds() is not None,
            "reason": "" if _nessus_creds() else "set NESSUS_ACCESS_KEY/NESSUS_SECRET_KEY (generate in Nessus UI)",
        },
    }


# ───────────────────────── Nuclei ─────────────────────────
def run_nuclei(target: str, out_dir: str) -> str:
    if not _nuclei_ok():
        raise ScannerError("nuclei binary not found")
    out = os.path.join(out_dir, "nuclei.jsonl")
    cmd = [NUCLEI_BIN, "-u", target, "-jsonl", "-o", out, "-silent", "-no-color"]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=NUCLEI_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ScannerError(f"nuclei timed out after {NUCLEI_TIMEOUT}s")
    except OSError as e:
        raise ScannerError(f"nuclei failed to start: {e}")
    if not os.path.exists(out):
        # Nuclei writes nothing when there are zero matches — emit an empty file
        # so the ingest step records a clean (0-finding) upload rather than error.
        open(out, "w").close()
    return out


# ───────────────────────── OWASP ZAP ─────────────────────────
def run_zap(target: str, out_dir: str) -> str:
    if not _zap_ok():
        raise ScannerError("zaproxy/zap.sh not found")
    out = os.path.join(out_dir, "zap.xml")
    # Headless quick scan: spider + passive + active, XML report (parser reads XML).
    cmd = [ZAP_BIN, "-cmd", "-quickurl", target, "-quickout", out, "-quickprogress"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=ZAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ScannerError(f"ZAP timed out after {ZAP_TIMEOUT}s")
    except OSError as e:
        raise ScannerError(f"ZAP failed to start: {e}")
    if not os.path.exists(out):
        raise ScannerError(f"ZAP produced no report (exit {proc.returncode}): "
                           f"{(proc.stderr or proc.stdout or '')[:300]}")
    return out


# ───────────────────────── Nessus (API) ─────────────────────────
def _nessus_headers(ak: str, sk: str) -> dict:
    return {"X-ApiKeys": f"accessKey={ak}; secretKey={sk}",
            "Content-Type": "application/json"}


def _nessus_template_uuid(base: str, headers: dict) -> str:
    r = requests.get(f"{base}/editor/scan/templates", headers=headers, verify=False, timeout=30)
    r.raise_for_status()
    templates = r.json().get("templates", [])
    for pref in ("basic", "web_app", "advanced"):
        for t in templates:
            if t.get("name") == pref:
                return t["uuid"]
    if templates:
        return templates[0]["uuid"]
    raise ScannerError("no Nessus scan templates available")


def run_nessus(target: str, out_dir: str) -> str:
    creds = _nessus_creds()
    if not creds:
        raise ScannerError("Nessus credentials not set (NESSUS_ACCESS_KEY/NESSUS_SECRET_KEY)")
    base, ak, sk = creds
    headers = _nessus_headers(ak, sk)
    deadline = time.time() + NESSUS_TIMEOUT

    try:
        uuid = _nessus_template_uuid(base, headers)
        # Create + launch scan
        payload = {"uuid": uuid, "settings": {
            "name": f"VulnTriage auto scan {target}", "enabled": True, "text_targets": target}}
        r = requests.post(f"{base}/scans", json=payload, headers=headers, verify=False, timeout=30)
        r.raise_for_status()
        scan_id = r.json()["scan"]["id"]
        requests.post(f"{base}/scans/{scan_id}/launch", headers=headers, verify=False, timeout=30).raise_for_status()

        # Poll until complete
        while True:
            if time.time() > deadline:
                raise ScannerError(f"Nessus scan timed out after {NESSUS_TIMEOUT}s")
            r = requests.get(f"{base}/scans/{scan_id}", headers=headers, verify=False, timeout=30)
            status = r.json().get("info", {}).get("status", "")
            if status == "completed":
                break
            if status in ("canceled", "aborted"):
                raise ScannerError(f"Nessus scan {status}")
            time.sleep(15)

        # Export as .nessus and download
        r = requests.post(f"{base}/scans/{scan_id}/export", json={"format": "nessus"},
                          headers=headers, verify=False, timeout=30)
        r.raise_for_status()
        file_id = r.json()["file"]
        while True:
            if time.time() > deadline:
                raise ScannerError("Nessus export timed out")
            r = requests.get(f"{base}/scans/{scan_id}/export/{file_id}/status",
                             headers=headers, verify=False, timeout=30)
            if r.json().get("status") == "ready":
                break
            time.sleep(5)
        r = requests.get(f"{base}/scans/{scan_id}/export/{file_id}/download",
                         headers=headers, verify=False, timeout=120)
        r.raise_for_status()
    except requests.RequestException as e:
        raise ScannerError(f"Nessus API error: {e}")

    out = os.path.join(out_dir, "nessus.nessus")
    with open(out, "wb") as f:
        f.write(r.content)
    return out


_RUNNERS = {"nuclei": run_nuclei, "zap": run_zap, "nessus": run_nessus}


def run_scanner(name: str, target: str, out_dir: str) -> str:
    """Run one scanner by name and return its native report path."""
    runner = _RUNNERS.get(name)
    if not runner:
        raise ScannerError(f"unknown scanner '{name}'")
    os.makedirs(out_dir, exist_ok=True)
    return runner(target, out_dir)
