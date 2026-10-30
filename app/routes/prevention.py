"""Prevention and Remediation Guide Routes Module

Provides comprehensive engineering guides, server configurations, framework snippets,
and testing instructions for preventing clickjacking vulnerabilities.
"""

from flask import Blueprint, render_template

prevention_bp = Blueprint("prevention", __name__)


@prevention_bp.route("/prevention")
def prevention_guide():
    """Renders the in-depth anti-framing prevention, configuration, and verification guide."""
    return render_template("prevention.html")
