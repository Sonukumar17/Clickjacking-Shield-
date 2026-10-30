"""History Management Routes Module

Handles historical scan records, multi-parameter search, outcome filtering,
record deletion, and bulk cleanup with CSRF verification.
"""

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from app.models import AssessmentRepository

history_bp = Blueprint("history", __name__)


@history_bp.route("/history")
def history_list():
    """Renders the historical scan records table with search and filtering controls."""
    search_query = request.args.get("q", "").strip()
    outcome_filter = request.args.get("outcome", "all").strip()
    sort_by = request.args.get("sort", "date_desc").strip()

    repo = AssessmentRepository(current_app.config["DATABASE_PATH"])
    assessments = repo.list_assessments(
        search_query=search_query if search_query else None,
        outcome_filter=outcome_filter if outcome_filter != "all" else None,
        sort_by=sort_by,
        limit=150,
    )
    stats = repo.get_statistics()

    return render_template(
        "history.html",
        assessments=assessments,
        stats=stats,
        search_query=search_query,
        outcome_filter=outcome_filter,
        sort_by=sort_by,
    )


@history_bp.route("/history/delete/<assessment_id>", methods=["POST"])
def delete_assessment(assessment_id: str):
    """Deletes an assessment record by its unique ID."""
    repo = AssessmentRepository(current_app.config["DATABASE_PATH"])
    deleted = repo.delete(assessment_id)
    if deleted:
        flash("Assessment record removed successfully.", "success")
    else:
        flash("Record not found or already deleted.", "warning")

    return redirect(url_for("history.history_list"))


@history_bp.route("/history/clear-all", methods=["POST"])
def clear_all_history():
    """Deletes all stored historical assessment records."""
    repo = AssessmentRepository(current_app.config["DATABASE_PATH"])
    count = repo.clear_all()
    flash(f"All scan history cleared ({count} records deleted).", "info")
    return redirect(url_for("history.history_list"))
