"""Quick DB diagnostic — run from backend folder."""
import os, sys
sys.path.insert(0, r'C:\Users\Dell\Downloads\FYP\backend')
os.chdir(r'C:\Users\Dell\Downloads\FYP\backend')

from dotenv import load_dotenv
load_dotenv()

from app import create_app, db
from app.models.normalized_finding import NormalizedFinding
from app.models.vulnerability import Vulnerability
from app.models.scanner_upload import ScannerUpload
from app.models.report import Report
from sqlalchemy import select, text

app = create_app('development')
with app.app_context():
    nf_count  = db.session.execute(select(db.func.count()).select_from(NormalizedFinding)).scalar()
    v_count   = db.session.execute(select(db.func.count()).select_from(Vulnerability)).scalar()
    up_count  = db.session.execute(select(db.func.count()).select_from(ScannerUpload)).scalar()
    rpt_count = db.session.execute(select(db.func.count()).select_from(Report)).scalar()

    print(f"\n=== Row counts ===")
    print(f"  scanner_uploads      : {up_count}")
    print(f"  vulnerabilities      : {v_count}")
    print(f"  normalized_findings  : {nf_count}")
    print(f"  reports              : {rpt_count}")

    # Show all uploads
    uploads = ScannerUpload.query.all()
    print(f"\n=== Uploads ===")
    for u in uploads:
        print(f"  id={u.id}  user_id={u.user_id}  file={u.original_filename}  status={u.status}  vulns={u.vulnerability_count}")

    # Show first few NormalizedFindings and their chain
    print(f"\n=== First 3 NormalizedFindings ===")
    nfs = NormalizedFinding.query.limit(3).all()
    for nf in nfs:
        v  = db.session.get(Vulnerability, nf.vulnerability_id)
        up = db.session.get(ScannerUpload, v.upload_id) if v else None
        print(f"  nf.id={nf.id}  title={nf.title[:40]}  vuln_id={nf.vulnerability_id}  upload_id={v and v.upload_id}  user_id={up and up.user_id}")

    # Show latest report
    rpt = Report.query.order_by(Report.id.desc()).first()
    if rpt:
        print(f"\n=== Latest Report ===")
        print(f"  id={rpt.id}  status={rpt.status}  user_id={rpt.user_id}  upload_ids={rpt.upload_ids}  total_findings={rpt.total_findings}")

    # Simulate the exact query used in report generation
    if rpt and rpt.upload_ids:
        uid = rpt.user_id
        ups = [int(i) for i in rpt.upload_ids]
        print(f"\n=== Simulating _load_findings(user_id={uid}, upload_ids={ups}) ===")
        stmt = (
            select(NormalizedFinding)
            .join(Vulnerability,  NormalizedFinding.vulnerability_id == Vulnerability.id)
            .join(ScannerUpload,  Vulnerability.upload_id == ScannerUpload.id)
            .where(ScannerUpload.user_id == uid)
            .where(ScannerUpload.id.in_(ups))
        )
        findings = list(db.session.execute(stmt).scalars().all())
        print(f"  Result: {len(findings)} findings")

    # Also try without upload_ids filter
    print(f"\n=== _load_findings with NO upload filter (all user findings) ===")
    if rpt:
        stmt2 = (
            select(NormalizedFinding)
            .join(Vulnerability,  NormalizedFinding.vulnerability_id == Vulnerability.id)
            .join(ScannerUpload,  Vulnerability.upload_id == ScannerUpload.id)
            .where(ScannerUpload.user_id == rpt.user_id)
        )
        all_findings = list(db.session.execute(stmt2).scalars().all())
        print(f"  Result: {len(all_findings)} findings")
