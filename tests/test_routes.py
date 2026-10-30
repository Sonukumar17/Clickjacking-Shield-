"""Integration Tests for Application Routes, Lab, and Security Middleware

Validates HTTP views, educational demonstration targets, report downloads,
and CSRF protection boundaries.
"""

from unittest.mock import MagicMock
from app.models import AssessmentRepository


class TestWebViews:
    """Tests all standard informational and analytical web pages."""

    def test_home_page(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "Clickjacking Detection & Prevention" in html
        assert "Start Security Assessment" in html
        assert "Ethical Authorization Notice" in html

    def test_dashboard_page(self, client):
        resp = client.get("/dashboard")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "Security Assessment Dashboard" in html
        assert "Total Assessments" in html

    def test_scanner_page(self, client):
        resp = client.get("/scanner")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "Security Header Scanner" in html
        assert "Target Website URL" in html

    def test_prevention_page(self, client):
        resp = client.get("/prevention")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "Clickjacking Prevention & Remediation" in html
        assert "frame-ancestors 'none';" in html
        assert "X-Frame-Options: DENY" in html

    def test_about_page(self, client):
        resp = client.get("/about")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "About the ClickjackShield Platform" in html
        assert "RFC 7034" in html

    def test_chatbot_page(self, client):
        resp = client.get("/chatbot")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "ShieldBot" in html
        assert "Rule-Based Cybersecurity Assistant" in html

    def test_chatbot_api_endpoint(self, client):
        resp = client.post("/api/chatbot", json={"message": "What is clickjacking?"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert data["received"] == "What is clickjacking?"

    def test_chatbot_api_empty_message(self, client):
        resp = client.post("/api/chatbot", json={"message": ""})
        assert resp.status_code == 400
        data = resp.get_json()
        assert data["success"] is False


class TestEducationalLabRoutes:
    """Tests the safe educational laboratory and mock demonstration target endpoints."""

    def test_lab_workspace(self, client):
        resp = client.get("/lab")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        assert "Safe Clickjacking Educational Laboratory" in html
        assert "Attacker Controlled Framing Sandbox" in html

    def test_unprotected_target_omits_anti_framing_headers(self, client):
        resp = client.get("/lab/demo-target-unprotected")
        assert resp.status_code == 200
        # Must NOT have anti-framing headers
        assert "X-Frame-Options" not in resp.headers
        assert "Content-Security-Policy" not in resp.headers
        html = resp.get_data(as_text=True)
        assert "Mock Target A (Unprotected)" in html

    def test_protected_target_enforces_anti_framing_headers(self, client):
        resp = client.get("/lab/demo-target-protected")
        assert resp.status_code == 200
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Content-Security-Policy") == "frame-ancestors 'none';"
        html = resp.get_data(as_text=True)
        assert "Mock Target B (Protected)" in html

    def test_harmless_demo_action(self, client):
        resp = client.post("/lab/demo-action", json={"action": "test_click"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "success"
        assert "Simulated harmless transfer" in data["message"]


class TestReportExportsAndCSRF:
    """Tests report views, JSON/PDF downloads, and CSRF protection."""

    def test_report_views(self, client, app, sample_assessment_data):
        with app.app_context():
            repo = AssessmentRepository(app.config["DATABASE_PATH"])
            rec_id = repo.save(sample_assessment_data)

        # HTML report view
        html_resp = client.get(f"/report/{rec_id}")
        assert html_resp.status_code == 200
        assert "Audit Report: example.com" in html_resp.get_data(as_text=True)

        # JSON export
        json_resp = client.get(f"/report/{rec_id}/json")
        assert json_resp.status_code == 200
        assert json_resp.headers.get("Content-Type") == "application/json"
        assert json_resp.get_json()["hostname"] == "example.com"

        # PDF export
        pdf_resp = client.get(f"/report/{rec_id}/pdf")
        assert pdf_resp.status_code == 200
        assert pdf_resp.headers.get("Content-Type") == "application/pdf"
        assert pdf_resp.data.startswith(b"%PDF-")

    def test_csrf_protection_blocks_unauthorized_post(self, client):
        # State-changing POST to /history/clear-all without CSRF token should be rejected with 403
        resp = client.post("/history/clear-all")
        assert resp.status_code == 403

    def test_csrf_token_generation_and_validation(self, client):
        # 1. Establish session by loading a page
        get_resp = client.get("/scanner")
        assert get_resp.status_code == 200

        with client.session_transaction() as sess:
            csrf_token = sess.get("_csrf_token")
            assert csrf_token is not None

        # 2. Issue state-changing request with valid CSRF token in header
        resp = client.post(
            "/history/clear-all",
            headers={"X-CSRF-Token": csrf_token},
            follow_redirects=True,
        )
        assert resp.status_code == 200
