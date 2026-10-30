"""Report Generation and Export Routes Module

Provides detailed audit reports in HTML, structured JSON, and downloadable PDF formats.
"""

from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    jsonify,
    render_template,
    send_file,
)
from app.models import AssessmentRepository
from app.services.pdf_report import generate_pdf_report

report_bp = Blueprint("reports", __name__)


@report_bp.route("/report/<assessment_id>")
def view_report(assessment_id: str):
    """Renders the comprehensive security assessment report page."""
    repo = AssessmentRepository(current_app.config["DATABASE_PATH"])
    assessment = repo.get_by_id(assessment_id)
    if not assessment:
        abort(404, description="Assessment report not found.")

    return render_template("report.html", assessment=assessment)


@report_bp.route("/report/<assessment_id>/json")
def export_json(assessment_id: str):
    """Exports the structured assessment data as a downloadable JSON document."""
    repo = AssessmentRepository(current_app.config["DATABASE_PATH"])
    assessment = repo.get_by_id(assessment_id)
    if not assessment:
        abort(404, description="Assessment report not found.")

    response = jsonify(assessment)
    filename = f"clickjack-audit-{assessment['hostname']}-{assessment_id[:8]}.json"
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response


@report_bp.route("/report/<assessment_id>/pdf")
def export_pdf(assessment_id: str):
    """Exports an executive-ready cybersecurity audit report in PDF format."""
    repo = AssessmentRepository(current_app.config["DATABASE_PATH"])
    assessment = repo.get_by_id(assessment_id)
    if not assessment:
        abort(404, description="Assessment report not found.")

    pdf_buffer = generate_pdf_report(assessment)
    filename = f"clickjack-report-{assessment['hostname']}-{assessment_id[:8]}.pdf"

    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )
