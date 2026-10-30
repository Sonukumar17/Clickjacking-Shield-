"""Pytest Test Configuration and Fixtures Module

Sets up isolated temporary database and test application fixtures.
"""

import pytest
from app import create_app
from app.models import AssessmentRepository, init_db


@pytest.fixture
def app(tmp_path):
    """Creates a fresh test Flask application configured with temporary test database."""
    db_file = str(tmp_path / "test_assessments.db")
    init_db(db_file)

    test_app = create_app(config_name="testing")
    test_app.config.update({
        "TESTING": True,
        "DATABASE_PATH": db_file,
        "WTF_CSRF_ENABLED": False,
        "SCANNER_TIMEOUT": 2,
    })

    yield test_app


@pytest.fixture
def client(app):
    """Test client for issuing requests."""
    return app.test_client()


@pytest.fixture
def repo(app):
    """Assessment repository initialized against the test database."""
    return AssessmentRepository(app.config["DATABASE_PATH"])


@pytest.fixture
def sample_assessment_data():
    """Sample assessment record payload for testing."""
    return {
        "id": "test-uuid-12345",
        "url": "https://example.com/",
        "final_url": "https://example.com/",
        "hostname": "example.com",
        "ip_address": "93.184.216.34",
        "scan_timestamp": "2026-10-30T12:00:00Z",
        "http_status": 200,
        "outcome": "Protected",
        "confidence": "High",
        "xfo_present": True,
        "xfo_raw": "DENY",
        "xfo_status": "Protected (DENY)",
        "xfo_details": "Configured with DENY.",
        "csp_present": True,
        "csp_raw": "frame-ancestors 'none';",
        "csp_frame_ancestors": "frame-ancestors 'none'",
        "csp_status": "Protected (frame-ancestors 'none')",
        "csp_details": "Strict framing denial.",
        "other_headers": {
            "strict_transport_security": {"present": True, "value": "max-age=31536000"},
            "x_content_type_options": {"present": True, "value": "nosniff"},
        },
        "redirects": [],
        "explanation": "Target implements recognized anti-framing mechanisms.",
        "remediation": "Maintain current posture.",
    }
