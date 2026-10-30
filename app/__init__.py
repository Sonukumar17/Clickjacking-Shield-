"""Clickjacking Detection and Prevention Platform Application Factory

Initializes the Flask application, wires blueprints, configures defensive security
headers, enforces CSRF checks, and registers error handlers.
"""

from datetime import datetime, timezone
import os
import sys

# Ensure site-packages path is accessible across all Python runtimes
user_site = os.path.expanduser(r"~\AppData\Local\Programs\Python\Python314\Lib\site-packages")
if os.path.isdir(user_site) and user_site not in sys.path:
    sys.path.insert(0, user_site)

from flask import Flask, jsonify, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from config import config_by_name
from app.models import init_db
from app.security import (
    apply_defensive_headers,
    check_csrf_protection,
    generate_csrf_token,
)


def create_app(config_name: str = "default") -> Flask:
    """Application factory for the ClickjackShield platform."""
    app = Flask(__name__)

    # Determine configuration class
    env_config = os.environ.get("FLASK_ENV", config_name)
    cfg_class = config_by_name.get(env_config, config_by_name["default"])
    app.config.from_object(cfg_class)

    # Configure ProxyFix for reverse-proxy deployments (Render, Heroku, Nginx)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    # Initialize SQLite database schema
    init_db(app.config["DATABASE_PATH"])

    # Register Context Processors for Jinja Templates
    @app.context_processor
    def inject_template_globals():
        return {
            "csrf_token": generate_csrf_token,
            "current_year": datetime.now(timezone.utc).year,
        }

    # Register Security Middleware
    app.before_request(check_csrf_protection)
    app.after_request(apply_defensive_headers)

    # Register Blueprints
    from app.routes.main import main_bp
    from app.routes.scan import scan_bp
    from app.routes.reports import report_bp
    from app.routes.history import history_bp
    from app.routes.lab import lab_bp
    from app.routes.prevention import prevention_bp
    from app.routes.chatbot import chatbot_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(history_bp)
    app.register_blueprint(lab_bp)
    app.register_blueprint(prevention_bp)
    app.register_blueprint(chatbot_bp)

    # Register Custom Error Handlers
    @app.errorhandler(400)
    def bad_request_error(e):
        if request.is_json:
            return jsonify({"error": "Bad Request", "message": str(e.description)}), 400
        return render_template("errors/400.html", error=e), 400

    @app.errorhandler(403)
    def forbidden_error(e):
        if request.is_json:
            return jsonify({"error": "Forbidden", "message": str(e.description)}), 403
        return render_template("errors/403.html", error=e), 403

    @app.errorhandler(404)
    def not_found_error(e):
        if request.is_json:
            return jsonify({"error": "Not Found", "message": str(e.description)}), 404
        return render_template("errors/404.html", error=e), 404

    @app.errorhandler(429)
    def rate_limit_error(e):
        if request.is_json:
            return jsonify({"error": "Rate Limit Exceeded", "message": str(e.description)}), 429
        return render_template("errors/429.html", error=e), 429

    @app.errorhandler(500)
    def internal_error(e):
        if request.is_json:
            return jsonify({"error": "Internal Server Error", "message": "An unexpected error occurred."}), 500
        return render_template("errors/500.html", error=e), 500

    return app
