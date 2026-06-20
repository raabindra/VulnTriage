"""
Pipeline orchestration route.

Triggers the full triage pipeline for a completed upload:
  normalise -> deduplicate -> map CWEs -> enrich with NVD
  -> ML predict -> confidence score -> optional PoC validation
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from app.models.scanner_upload import ScannerUpload
from app.engines.normalisation import NormalisationEngine
from app.engines.deduplication import DeduplicationEngine
from app.engines.cwe_mapper import CweMapper
from app.engines.nvd_enrichment import NvdEnrichmentEngine
from app.engines.cwe_cvss_enrichment import CweCvssEnrichmentEngine
from app.engines.confidence_engine import ConfidenceEngine
from app.ml.predictor import VulnerabilityPredictor

pipeline_bp = Blueprint("pipeline", __name__)


@pipeline_bp.post("/run/<int:upload_id>")
@jwt_required()
def run_pipeline(upload_id: int):
    user_id = int(get_jwt_identity())
    upload = ScannerUpload.query.filter_by(id=upload_id, user_id=user_id).first_or_404()

    if upload.status != "completed":
        return jsonify({"error": "Upload must be in 'completed' state to run pipeline"}), 400

    results = {}

    # 1. Normalise
    norm = NormalisationEngine()
    results["normalised"] = norm.normalise_upload(upload_id)

    # 2. Deduplicate (across all user findings)
    dedup = DeduplicationEngine()
    results["duplicates_removed"] = dedup.merge_duplicates()

    # 3. Map CWEs
    mapper = CweMapper()
    results["cwe_mapped"] = mapper.map_all_unclassified()

    # 4. NVD enrichment
    nvd = NvdEnrichmentEngine()
    results["nvd_enriched"] = nvd.enrich_all_pending()

    # 4b. CWE→CVSS-vector enrichment — give vector-less findings (e.g. ZAP) a
    #     plausible, data-derived CVSS vector so the ML model has real features.
    cwe_cvss = CweCvssEnrichmentEngine()
    results["cwe_vector_inferred"] = cwe_cvss.enrich_all_pending()

    # 5. ML prioritisation
    try:
        predictor = VulnerabilityPredictor()
        results["ml_predicted"] = predictor.predict_all_unpredicted()
    except FileNotFoundError as exc:
        results["ml_predicted"] = 0
        results["ml_warning"] = str(exc)

    # 5b. Optional exploit lookup (Exploit-DB via searchsploit)
    search_exploits = request.json.get("search_exploits", False) if request.is_json else False
    if search_exploits:
        from app.engines.exploit_search import ExploitSearchEngine
        results["exploit_search"] = ExploitSearchEngine().enrich_all()

    # 6. Confidence scoring
    engine = ConfidenceEngine()
    results["confidence_scored"] = engine.score_all()

    # 7. Optional PoC validation
    run_poc = request.json.get("run_poc", False) if request.is_json else False
    poc_scope = request.json.get("poc_scope") if request.is_json else None
    if run_poc:
        from app.engines.poc_validator import PocValidator
        from app.models.normalized_finding import NormalizedFinding
        from app.models.vulnerability import Vulnerability
        validator = PocValidator(scope=poc_scope)
        owned_upload_ids = db.session.query(ScannerUpload.id).filter_by(user_id=user_id).subquery()
        findings = (
            NormalizedFinding.query
            .join(NormalizedFinding.source_vulnerability)
            .filter(Vulnerability.upload_id.in_(owned_upload_ids))
            .filter(NormalizedFinding.url.isnot(None))
            .limit(20)
            .all()
        )
        poc_count = 0
        for f in findings:
            try:
                validator.validate_finding(f)
                poc_count += 1
            except Exception:
                pass
        results["poc_validated"] = poc_count
        db.session.commit()

    # 7. Auto-generate PDF report
    from app.engines.report_generator import ReportGenerator
    from app.models.report import Report
    from datetime import datetime

    rpt = Report(
        user_id=user_id,
        title=f"Triage Report — {upload.original_filename} — {datetime.utcnow().strftime('%d %b %Y')}",
        report_type="pdf",
        status="pending",
        upload_ids=[upload_id],
    )
    db.session.add(rpt)
    db.session.commit()
    try:
        ReportGenerator().generate(rpt.id)
        results["report_id"] = rpt.id
    except Exception as exc:
        results["report_warning"] = str(exc)

    return jsonify({"upload_id": upload_id, "pipeline_results": results}), 200


@pipeline_bp.get("/ml/info")
@jwt_required()
def ml_info():
    predictor = VulnerabilityPredictor()
    return jsonify(predictor.model_info()), 200
