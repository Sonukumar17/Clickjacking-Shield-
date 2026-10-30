"""Main Routes Module: Landing Page, Dashboard, and About

Handles top-level navigation, cybersecurity posture metrics, and project documentation.
"""

from flask import Blueprint, current_app, render_template
from app.models import AssessmentRepository

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """Landing Home Page with product overview, feature highlights, and call to action."""
    repo = AssessmentRepository(current_app.config["DATABASE_PATH"])
    stats = repo.get_statistics()
    return render_template("index.html", stats=stats)


@main_bp.route("/dashboard")
def dashboard():
    """Security Assessment Dashboard with metric cards, Chart.js breakdown, and recent history."""
    repo = AssessmentRepository(current_app.config["DATABASE_PATH"])
    stats = repo.get_statistics()
    recent_scans = repo.list_assessments(limit=8, sort_by="date_desc")
    return render_template("dashboard.html", stats=stats, recent_scans=recent_scans)


@main_bp.route("/about")
def about():
    """Educational Overview, Methodology, RFC Standards, and Ethical Disclosure."""
    return render_template("about.html")
