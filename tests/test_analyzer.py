"""Unit Tests for Security Header Analyzer

Tests parsing and evaluation of X-Frame-Options, Content-Security-Policy frame-ancestors,
misconfigurations, conflicting directives, and overall posture scoring.
"""

from app.scanner.analyzer import SecurityAnalyzer


class TestXFrameOptionsAnalysis:
    """Tests evaluation of the X-Frame-Options response header."""

    def test_deny_directive(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={"x-frame-options": "DENY"},
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        assert res["outcome"] == "Protected"
        assert res["xfo_present"] is True
        assert res["xfo_status"] == "Protected (DENY)"
        assert res["xfo_directive"] == "DENY"

    def test_sameorigin_directive(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={"x-frame-options": "SAMEORIGIN"},
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        assert res["outcome"] == "Protected"
        assert res["xfo_status"] == "Protected (SAMEORIGIN)"

    def test_allow_from_deprecated(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={"x-frame-options": "ALLOW-FROM https://trusted.com"},
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        # Because ALLOW-FROM is deprecated and ignored in modern browsers,
        # it is considered ineffective without a valid CSP.
        assert res["outcome"] == "Potential Risk"
        assert "Deprecated" in res["xfo_status"]

    def test_conflicting_duplicate_values(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={"x-frame-options": "DENY, SAMEORIGIN"},
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        assert "Conflicting" in res["xfo_status"]
        assert res["outcome"] == "Potential Risk"

    def test_invalid_directive(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={"x-frame-options": "ALLOWALL"},
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        assert "Invalid" in res["xfo_status"]
        assert res["outcome"] == "Potential Risk"


class TestCSPAnalysis:
    """Tests evaluation of Content-Security-Policy frame-ancestors directive."""

    def test_csp_frame_ancestors_none(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={"content-security-policy": "default-src 'self'; frame-ancestors 'none';"},
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        assert res["outcome"] == "Protected"
        assert res["csp_present"] is True
        assert res["csp_status"] == "Protected (frame-ancestors 'none')"
        assert "'none'" in res["csp_sources"]

    def test_csp_frame_ancestors_self(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={"content-security-policy": "frame-ancestors 'self';"},
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        assert res["outcome"] == "Protected"
        assert "Protected" in res["csp_status"]

    def test_csp_wildcard_is_permissive(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={"content-security-policy": "frame-ancestors *;"},
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        assert res["outcome"] == "Potential Risk"
        assert "Permissive" in res["csp_status"]

    def test_csp_unquoted_keywords_misconfiguration(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={"content-security-policy": "frame-ancestors none;"},
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        assert res["outcome"] == "Potential Risk"
        assert "Unquoted" in res["csp_status"]

    def test_csp_missing_frame_ancestors(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={"content-security-policy": "default-src 'self'; script-src 'self'"},
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        assert res["outcome"] == "Potential Risk"
        assert "Missing frame-ancestors" in res["csp_status"]


class TestPrecedenceAndInconclusive:
    """Tests precedence explanations, secondary headers, and error handling."""

    def test_csp_and_xfo_precedence_note(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={
                "content-security-policy": "frame-ancestors 'none';",
                "x-frame-options": "DENY",
            },
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        assert res["outcome"] == "Protected"
        assert "Precedence" in res["precedence_note"]
        assert "ignore X-Frame-Options" in res["precedence_note"]

    def test_inconclusive_on_http_error(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={},
            http_status=500,
            url="https://example.com",
            final_url="https://example.com",
        )
        assert res["outcome"] == "Inconclusive"
        assert res["confidence"] == "Low"

    def test_secondary_headers_detected(self):
        res = SecurityAnalyzer.analyze_headers(
            headers={
                "strict-transport-security": "max-age=63072000; includeSubDomains",
                "x-content-type-options": "nosniff",
                "set-cookie": "session=xyz123; Secure; HttpOnly; SameSite=Lax",
            },
            http_status=200,
            url="https://example.com",
            final_url="https://example.com",
        )
        other = res["other_headers"]
        assert other["strict_transport_security"]["present"] is True
        assert other["x_content_type_options"]["present"] is True
        assert other["samesite_cookie"]["present"] is True
        assert other["samesite_cookie"]["value"] == "Lax"
