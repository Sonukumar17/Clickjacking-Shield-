"""Unit Tests for Safe HTTP Client and Redirect Handling

Tests redirect following, redirect hop depth limits, and SSRF defense on redirect destinations.
"""

from unittest.mock import MagicMock
import pytest
from app.scanner.client import SafeHttpClient
from app.scanner.validator import SecurityValidationError


class MockResponse:
    """Mock for requests.Response object."""

    def __init__(self, status_code: int, headers: dict, content: bytes = b""):
        self.status_code = status_code
        self.headers = headers
        self._content = content

    def iter_content(self, chunk_size=4096):
        yield self._content

    def close(self):
        pass


class TestSafeHttpClient:
    """Tests SafeHttpClient redirect tracing and safety limits."""

    def test_single_request_success(self, monkeypatch):
        # Mock URL validation & DNS
        monkeypatch.setattr(
            "app.scanner.client.validate_and_normalize_url",
            lambda url, allowed_ports: (url, "example.com", "93.184.216.34"),
        )

        mock_session = MagicMock()
        mock_session.get.return_value = MockResponse(
            status_code=200,
            headers={"X-Frame-Options": "DENY", "Content-Type": "text/html"},
        )
        monkeypatch.setattr("requests.Session", lambda: mock_session)

        client = SafeHttpClient(timeout=5)
        res = client.fetch("https://example.com")

        assert res["status_code"] == 200
        assert res["hostname"] == "example.com"
        assert res["headers"]["x-frame-options"] == "DENY"
        assert len(res["redirects"]) == 0

    def test_safe_redirect_followed(self, monkeypatch):
        # Mock URL validation to pass for public domains
        def mock_validate(url, allowed_ports):
            if "target" in url:
                return (url, "target.com", "93.184.216.35")
            return (url, "example.com", "93.184.216.34")

        monkeypatch.setattr("app.scanner.client.validate_and_normalize_url", mock_validate)

        # First request returns 301, second returns 200
        resp1 = MockResponse(301, {"Location": "https://target.com/home"})
        resp2 = MockResponse(200, {"Content-Security-Policy": "frame-ancestors 'none';"})

        mock_session = MagicMock()
        mock_session.get.side_effect = [resp1, resp2]
        monkeypatch.setattr("requests.Session", lambda: mock_session)

        client = SafeHttpClient(timeout=5, max_redirects=5)
        res = client.fetch("https://example.com")

        assert res["status_code"] == 200
        assert res["final_url"] == "https://target.com/home"
        assert len(res["redirects"]) == 1
        assert res["redirects"][0]["status_code"] == 301

    def test_ssrf_on_redirect_is_blocked(self, monkeypatch):
        # Allow initial URL, but when validating redirect location, raise SecurityValidationError
        call_count = [0]

        def mock_validate(url, allowed_ports):
            call_count[0] += 1
            if call_count[0] == 1:
                return ("https://public-site.com", "public-site.com", "93.184.216.34")
            # The second call is validating the redirect target (attacker redirected to metadata)
            raise SecurityValidationError("SSRF blocked: redirect points to cloud metadata")

        monkeypatch.setattr("app.scanner.client.validate_and_normalize_url", mock_validate)

        resp1 = MockResponse(302, {"Location": "https://169.254.169.254/latest/meta-data/"})

        mock_session = MagicMock()
        mock_session.get.return_value = resp1
        monkeypatch.setattr("requests.Session", lambda: mock_session)

        client = SafeHttpClient(timeout=5)
        with pytest.raises(SecurityValidationError, match="SSRF blocked"):
            client.fetch("https://public-site.com")

    def test_max_redirects_exceeded(self, monkeypatch):
        monkeypatch.setattr(
            "app.scanner.client.validate_and_normalize_url",
            lambda url, allowed_ports: (url, "loop.com", "93.184.216.34"),
        )

        mock_session = MagicMock()
        # Always return 302 to create an infinite loop
        mock_session.get.return_value = MockResponse(302, {"Location": "https://loop.com/next"})
        monkeypatch.setattr("requests.Session", lambda: mock_session)

        client = SafeHttpClient(timeout=5, max_redirects=3)
        with pytest.raises(SecurityValidationError, match="Exceeded maximum allowed redirects"):
            client.fetch("https://loop.com")
