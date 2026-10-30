"""Chatbot Routes Module

Provides the API endpoint for the rule-based cybersecurity chatbot
and the dedicated chatbot page view.
"""

from flask import Blueprint, jsonify, render_template, request

chatbot_bp = Blueprint("chatbot", __name__, url_prefix="")


@chatbot_bp.route("/chatbot", strict_slashes=False)
@chatbot_bp.route("/chat", strict_slashes=False)
@chatbot_bp.route("/bot", strict_slashes=False)
def chatbot_page():
    """Renders the dedicated full-page chatbot interface."""
    return render_template("chatbot.html")


@chatbot_bp.route("/api/chatbot", methods=["POST"])
def chatbot_response():
    """Accepts a user message — real keyword matching is done client-side in chatbot.js."""
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()

    if not message:
        return jsonify({"success": False, "error": "Empty message"}), 400

    return jsonify({"success": True, "received": message}), 200
