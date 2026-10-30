"""Application Security, CSRF Protection, and Rate Limiting Module

Implements defense-in-depth protections for the web application itself:
- Cryptographic CSRF token generation and validation.
- Defensive response security headers.
- Per-IP rate limiting for the scanner engine.
"""

import hmac
import secrets
import time
from collections import defaultdict
from functools import wraps
from typing import Dict, List
from flask import abort, current_app, g, jsonify, request, session


def generate_csrf_token() -> str:
    """Generates or retrieves a secure CSRF token stored in the user's session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def validate_csrf_token(token: str) -> bool:
    """Validates the submitted token against the session token using constant-time comparison."""
    expected = session.get("_csrf_token")
    if not expected or not token:
        return False
    return hmac.compare_digest(expected, token)


def check_csrf_protection() -> None:
    """Middleware checking CSRF token on all state-changing HTTP methods."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        # Exempt local lab simulated actions (self-contained mock sandbox)
        if request.path.startswith("/lab/demo-action"):
            return

        # Exempt chatbot API — rule-based, read-only, no state mutation
        if request.path.startswith("/api/chatbot"):
            return

        # Check request header or form body
        token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")

        if not token or not validate_csrf_token(token):
            if request.is_json or request.path.startswith("/api/"):
                response = jsonify({
                    "error": "CSRF validation failed",
                    "message": "Invalid or missing CSRF token. Please refresh the page and try again."
                })
                response.status_code = 403
                abort(response)
            else:
                abort(403, description="CSRF token validation failed. Refresh and try again.")


class SimpleRateLimiter:
    """Sliding-window in-memory rate limiter per client IP."""

    def __init__(self):
        self._requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str, limit: int = 30, window_seconds: int = 60) -> bool:
        """Determines if the client IP is within the allowed request quota."""
        now = time.time()
        cutoff = now - window_seconds

        # Clean expired timestamps
        self._requests[client_ip] = [ts for ts in self._requests[client_ip] if ts > cutoff]

        if len(self._requests[client_ip]) >= limit:
            return False

        self._requests[client_ip].append(now)
        return True


rate_limiter = SimpleRateLimiter()


def rate_limit_scans(f):
    """Decorator to enforce per-IP rate limiting on scanner endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        limit = current_app.config.get("RATE_LIMIT_PER_MINUTE", 30)
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
        # Handle comma-separated X-Forwarded-For
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        if not rate_limiter.is_allowed(client_ip, limit=limit, window_seconds=60):
            response = jsonify({
                "error": "Rate limit exceeded",
                "message": f"Scan request limit reached ({limit} scans/minute). Please wait before scanning again.",
            })
            response.status_code = 429
            return response

        return f(*args, **kwargs)

    return decorated_function


def apply_defensive_headers(response):
    """Applies hardened HTTP response security headers to all outgoing responses."""
    # Prevent MIME sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Referrer Policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Permissions Policy
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Cache control for sensitive dynamic dashboard content
    if request.path.startswith(("/scanner", "/report", "/dashboard")):
        response.headers["Cache-Control"] = "no-store, max-age=0"

    # Anti-framing policy for the scanner application itself:
    # Allow SAMEORIGIN only for the local educational lab demonstration
    if request.path.startswith("/lab/demo-target-unprotected"):
        # Intentionally omit anti-framing header for the unprotected mock demonstration page
        pass
    elif request.path.startswith("/lab/demo-target-protected"):
        # Explicitly protect the mock protected demonstration page
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none';"
    else:
        # Standard app protection: allow local framing only for the lab viewer on same origin
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'self';"

    return response
