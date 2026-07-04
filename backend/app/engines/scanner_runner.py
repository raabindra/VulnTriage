"""
Scanner runner — optional orchestration layer (Auto Scan).

VulnTriage's core remains a *triage* system over existing scanner output; this
module lets the app optionally DRIVE scanners against a target and collect their
native reports, which then feed the normal ingest+triage pipeline. It does not
implement any scanning itself — it shells out to the real tools.

Auto Scan supports **OWASP ZAP** and **Nuclei** (both run headless with no extra
setup). Nessus is intentionally NOT auto-launched: Nessus Essentials/Professional
block scan creation via the REST API, so Nessus is used in VulnTriage via the
normal flow instead — run it in the Nessus UI, export the .nessus file, and
upload it. (The nessus parser handles that report like any other.)

⚠️  Active scanning is intrusive. Only run against assets you are authorised to
test. The orchestrator enforces an authorisation acknowledgement / scope.

Each adapter returns the path to a native report file the existing parsers can
read (ZAP XML, Nuclei JSONL), or raises ScannerError.
"""

import os
import shutil
import socket
import subprocess

# Tool locations (allow override via env for non-standard installs).
ZAP_BIN = os.environ.get("ZAP_BIN") or shutil.which("zaproxy") or shutil.which("zap.sh")
NUCLEI_BIN = os.environ.get("NUCLEI_BIN") or shutil.which("nuclei") \
    or os.path.expanduser("~/go-workspace/bin/nuclei")

# Default per-scanner wall-clock limits (seconds); override via env.
ZAP_TIMEOUT = int(os.environ.get("ZAP_TIMEOUT", "900"))
NUCLEI_TIMEOUT = int(os.environ.get("NUCLEI_TIMEOUT", "600"))

# Scanners Auto Scan can drive. (Nessus is supported via manual export+upload.)
SUPPORTED_SCANNERS = ("zap", "nuclei")


class ScannerError(RuntimeError):
    pass


# ───────────────────────── availability ─────────────────────────
def _nuclei_ok() -> bool:
    return bool(NUCLEI_BIN and os.path.exists(NUCLEI_BIN))


def _zap_ok() -> bool:
    return bool(ZAP_BIN and os.path.exists(ZAP_BIN))


def scanner_availability() -> dict:
    """Which Auto Scan scanners can actually run right now."""
    return {
        "zap": {"available": _zap_ok(),
                "reason": "" if _zap_ok() else "zaproxy/zap.sh not found"},
        "nuclei": {"available": _nuclei_ok(),
                   "reason": "" if _nuclei_ok() else "nuclei binary not found"},
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
def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_zap(target: str, out_dir: str) -> str:
    if not _zap_ok():
        raise ScannerError("zaproxy/zap.sh not found")
    out = os.path.join(out_dir, "zap.xml")
    # Isolate each run: a private ZAP home dir + a free proxy port. This avoids
    # the common failure where a stale/concurrent ZAP holds the default port 8080
    # or the ~/.ZAP session lock, which makes -quickurl silently produce no report.
    home = os.path.join(out_dir, "zaphome")
    os.makedirs(home, exist_ok=True)
    cmd = [ZAP_BIN, "-cmd", "-dir", home, "-port", str(_free_port()),
           "-quickurl", target, "-quickout", out, "-quickprogress"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=ZAP_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ScannerError(f"ZAP timed out after {ZAP_TIMEOUT}s (raise ZAP_TIMEOUT for large targets)")
    except OSError as e:
        raise ScannerError(f"ZAP failed to start: {e}")
    if not os.path.exists(out):
        msg = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = " ".join(msg[-3:])[:300] if msg else "no output"
        raise ScannerError(f"ZAP produced no report (exit {proc.returncode}): {tail}")
    return out


_RUNNERS = {"nuclei": run_nuclei, "zap": run_zap}


def run_scanner(name: str, target: str, out_dir: str) -> str:
    """Run one scanner by name and return its native report path."""
    runner = _RUNNERS.get(name)
    if not runner:
        raise ScannerError(
            f"'{name}' is not an Auto Scan scanner. Supported: "
            f"{', '.join(SUPPORTED_SCANNERS)}. (Nessus: export a .nessus report "
            f"from the Nessus UI and upload it instead.)")
    os.makedirs(out_dir, exist_ok=True)
    return runner(target, out_dir)
