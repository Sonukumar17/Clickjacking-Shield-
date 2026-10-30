"""Scanner Routes Module

Handles URL submission, automated validation, HTTP fetching, header analysis,
and results rendering.
"""

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from app.models import AssessmentRepository
from app.scanner import (
    SafeHttpClient,
    SecurityAnalyzer,
    SecurityValidationError,
)
from app.security import rate_limit_scans

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/scanner")
def scanner_form():
    """Renders the interactive URL analysis scanner interface."""
    return render_template("scanner.html")


@scan_bp.route("/scan/run", methods=["POST"])
@rate_limit_scans
def run_scan():
    """Executes a defensive security scan against the provided URL.

    Accepts both JSON and standard form submissions.
    """
    if request.is_json:
        target_url = (request.json.get("url") or "").strip()
    else:
        target_url = (request.form.get("url") or "").strip()

    if not target_url:
        msg = "Please provide a valid website URL."
        if request.is_json:
            return jsonify({"success": False, "error": msg}), 400
        flash(msg, "danger")
        return redirect(url_for("scan.scanner_form"))

    client = SafeHttpClient(
        timeout=current_app.config.get("SCANNER_TIMEOUT", 6),
        max_redirects=current_app.config.get("MAX_REDIRECTS", 5),
        max_response_size=current_app.config.get("MAX_RESPONSE_SIZE", 524288),
        user_agent=current_app.config.get("USER_AGENT"),
        allowed_ports=current_app.config.get("ALLOWED_PORTS", [443]),
    )

    try:
        # Step 1: Safe HTTP Request with SSRF & Redirect verification
        http_result = client.fetch(target_url)

        # Step 2: In-depth Anti-Framing Header Analysis
        analysis = SecurityAnalyzer.analyze_headers(
            headers=http_result["headers"],
            http_status=http_result["status_code"],
            url=http_result["url"],
            final_url=http_result["final_url"],
        )

        # Merge metadata
        assessment_record = {
            **analysis,
            "hostname": http_result["hostname"],
            "ip_address": http_result["ip_address"],
            "redirects": http_result["redirects"],
        }

        # Step 3: Persist Assessment in Database
        repo = AssessmentRepository(current_app.config["DATABASE_PATH"])
        assessment_id = repo.save(assessment_record)

        if request.is_json:
            return jsonify({
                "success": True,
                "id": assessment_id,
                "redirect_url": url_for("scan.scan_results", assessment_id=assessment_id),
                "data": assessment_record,
            })

        return redirect(url_for("scan.scan_results", assessment_id=assessment_id))

    except SecurityValidationError as e:
        error_msg = str(e)
        if request.is_json:
            return jsonify({"success": False, "error": error_msg}), 400
        flash(f"Security Validation Error: {error_msg}", "danger")
        return redirect(url_for("scan.scanner_form"))

    except Exception as e:
        error_msg = f"Unexpected scan failure: {e}"
        if request.is_json:
            return jsonify({"success": False, "error": error_msg}), 500
        flash(error_msg, "danger")
        return redirect(url_for("scan.scanner_form"))


@scan_bp.route("/scan/results/<assessment_id>")
def scan_results(assessment_id: str):
    """Renders the completed scan assessment results page."""
    repo = AssessmentRepository(current_app.config["DATABASE_PATH"])
    assessment = repo.get_by_id(assessment_id)
    if not assessment:
        abort(404, description="Assessment record not found.")

    return render_template("scan_results.html", assessment=assessment)
