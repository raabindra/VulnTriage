"""Auto Scan orchestrator tests — scanners are mocked, nothing real is scanned."""

import os
import shutil
import pytest

from app import db
from app.engines import auto_scan
from app.engines.auto_scan import AutoScanOrchestrator, AutoScanError
from app.engines.scanner_runner import scanner_availability
from app.models.user import User

_SAMPLE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),  # FYP/
    "samples", "zap-sample.xml",
)


def test_scanner_availability_shape():
    a = scanner_availability()
    assert set(a) == {"nuclei", "zap"}   # Nessus is not auto-launched
    for v in a.values():
        assert "available" in v and "reason" in v


def test_nessus_not_an_autoscan_scanner():
    from app.engines.scanner_runner import run_scanner, ScannerError
    with pytest.raises(ScannerError):
        run_scanner("nessus", "http://t", "/tmp")


def test_autoscan_requires_authorisation(app):
    with pytest.raises(AutoScanError):
        AutoScanOrchestrator().run("http://t", ["zap"], 1, authorise=False)


def test_autoscan_requires_target(app):
    with pytest.raises(AutoScanError):
        AutoScanOrchestrator().run("", ["zap"], 1, authorise=True)


@pytest.mark.skipif(not os.path.exists(_SAMPLE), reason="sample report missing")
def test_autoscan_end_to_end_mocked(app, monkeypatch):
    # Mock availability + the actual scanner run (return the sample ZAP report).
    monkeypatch.setattr(auto_scan, "scanner_availability",
                        lambda: {"zap": {"available": True, "reason": ""}})

    def fake_run(name, target, out_dir):
        dest = os.path.join(out_dir, "zap.xml")
        shutil.copyfile(_SAMPLE, dest)
        return dest
    monkeypatch.setattr(auto_scan, "run_scanner", fake_run)

    u = User(username="t", email="t@t.local", role="analyst")
    u.set_password("x")
    db.session.add(u)
    db.session.commit()

    res = AutoScanOrchestrator().run("http://testphp.vulnweb.com", ["zap"], u.id,
                                     authorise=True)
    assert res["scanners"]["zap"]["status"] == "ok"
    assert res["scanners"]["zap"]["findings"] >= 1
    assert res["confidence_scored"] >= 1
    assert "cwe_vector_inferred" in res
