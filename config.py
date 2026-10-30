"""Application Configuration Module

Defines configuration classes for Development, Testing, and Production environments.
Handles environment variables and enforces safe operational defaults.
"""

import os
from pathlib import Path
import secrets

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "clickjack-def-development-fallback-key-2026")
    DATABASE_PATH = os.environ.get(
        "DATABASE_PATH",
        str(BASE_DIR / "clickjack_defense.db")
    )
    
    # Session Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # Set to True in ProductionConfig
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours

    # Scanner Security Configuration
    SCANNER_TIMEOUT = int(os.environ.get("SCANNER_TIMEOUT_SECONDS", 6))
    MAX_REDIRECTS = int(os.environ.get("MAX_REDIRECTS", 5))
    MAX_RESPONSE_SIZE = int(os.environ.get("MAX_RESPONSE_SIZE_BYTES", 524288))  # 512 KB
    ALLOWED_PORTS = [int(p.strip()) for p in os.environ.get("SCANNER_ALLOWED_PORTS", "443").split(",") if p.strip()]
    USER_AGENT = "ClickjackShield-Audit-Scanner/1.0 (+https://localhost/about; Educational Security Research)"
    
    # Rate Limiting (per IP per minute for scan endpoints)
    RATE_LIMIT_PER_MINUTE = int(os.environ.get("RATE_LIMIT_PER_MINUTE", 30))

    # Testing flag
    TESTING = False
    DEBUG = False


class DevelopmentConfig(Config):
    """Development environment settings."""
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class TestingConfig(Config):
    """Automated testing environment settings."""
    TESTING = True
    DEBUG = False
    DATABASE_PATH = ":memory:"
    SECRET_KEY = "test-secret-key-for-automated-tests"
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    """Hardened production environment settings."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    
    def __init__(self):
        secret = os.environ.get("FLASK_SECRET_KEY")
        if not secret or "fallback" in secret:
            # Generate a secure fallback secret if not explicitly provided
            self.SECRET_KEY = secrets.token_hex(32)
        else:
            self.SECRET_KEY = secret


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
