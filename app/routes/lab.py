"""Safe Clickjacking Demonstration Lab Routes Module

Provides a strictly isolated, educational laboratory environment demonstrating
UI redressing against controlled local mock targets with harmless simulated actions.
"""

from flask import Blueprint, jsonify, make_response, render_template, request

lab_bp = Blueprint("lab", __name__)


@lab_bp.route("/lab")
def lab_workspace():
    """Main interactive clickjacking laboratory workspace."""
    return render_template("lab.html")


@lab_bp.route("/lab/demo-target-unprotected")
def demo_target_unprotected():
    """Page A: Mock vulnerable target page.

    Intentionally served WITHOUT anti-framing headers to demonstrate successful
    embedding within an iframe for educational analysis.
    """
    response = make_response(render_template("lab_target_unprotected.html"))
    # Explicitly clear any anti-framing headers that might be set by global middleware
    response.headers.pop("X-Frame-Options", None)
    response.headers.pop("Content-Security-Policy", None)
    return response


@lab_bp.route("/lab/demo-target-protected")
def demo_target_protected():
    """Page B: Mock protected target page.

    Protected with strict anti-framing headers (CSP frame-ancestors 'none' and X-Frame-Options: DENY)
    to demonstrate browser-enforced blocking.
    """
    response = make_response(render_template("lab_target_protected.html"))
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none';"
    return response


@lab_bp.route("/lab/demo-action", methods=["POST"])
def demo_action():
    """Harmless simulated action endpoint for the educational laboratory.

    Simulates a state change in the demo account without any real-world impact.
    """
    action = request.json.get("action") if request.is_json else request.form.get("action")
    return jsonify({
        "status": "success",
        "action": action or "harmless_demo_transfer",
        "message": "Simulated harmless transfer of 0.00 DEMO tokens executed in local sandbox.",
        "note": "Notice how the click intercepted by the transparent overlay triggered this local mock event!",
    })
