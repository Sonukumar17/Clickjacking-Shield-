"""Unit Tests for Target URL Validation and SSRF Defenses

Validates IP address screening, hostname constraints, port filtering,
and protocol restrictions.
"""

import ipaddress
import pytest
from app.scanner.validator import (
    SecurityValidationError,
    is_ip_disallowed,
    validate_and_normalize_url,
)


class TestIPFiltering:
    """Tests the is_ip_disallowed helper against IPv4 and IPv6 networks."""

    @pytest.mark.parametrize(
        "ip_str",
        [
            "127.0.0.1",       # Loopback
            "127.255.255.255", # Loopback edge
            "10.0.0.1",        # RFC 1918 Class A
            "172.16.0.1",      # RFC 1918 Class B
            "172.31.255.255",  # RFC 1918 Class B
            "192.168.1.1",     # RFC 1918 Class C
            "169.254.169.254", # AWS/GCP/Azure Cloud Metadata
            "169.254.1.1",     # Link-Local
            "100.64.0.1",      # Carrier-Grade NAT (RFC 6598)
            "0.0.0.0",         # Unspecified
            "224.0.0.1",       # Multicast
            "240.0.0.1",       # Reserved
            "::1",             # IPv6 Loopback
            "fe80::1",         # IPv6 Link-Local
            "fc00::1",         # IPv6 Unique Local
        ],
    )
    def test_disallowed_private_ips(self, ip_str):
        ip_obj = ipaddress.ip_address(ip_str)
        assert is_ip_disallowed(ip_obj) is True, f"IP {ip_str} should be disallowed"

    @pytest.mark.parametrize(
        "ip_str",
        [
            "93.184.216.34",  # example.com
            "8.8.8.8",        # Google DNS
            "1.1.1.1",        # Cloudflare DNS
            "140.82.112.4",   # GitHub
            "2606:4700:4700::1111", # Cloudflare IPv6
        ],
    )
    def test_allowed_public_ips(self, ip_str):
        ip_obj = ipaddress.ip_address(ip_str)
        assert is_ip_disallowed(ip_obj) is False, f"Public IP {ip_str} should be allowed"


class TestUrlValidation:
    """Tests validate_and_normalize_url with valid and hostile inputs."""

    def test_valid_https_url(self, monkeypatch):
        # Mock DNS resolution to avoid network reliance in unit tests
        monkeypatch.setattr(
            "app.scanner.validator.resolve_hostname_safely",
            lambda host: "93.184.216.34",
        )
        norm_url, hostname, ip = validate_and_normalize_url("https://example.com/test?page=1")
        assert norm_url == "https://example.com/test?page=1"
        assert hostname == "example.com"
        assert ip == "93.184.216.34"

    def test_missing_scheme_auto_prepends_https(self, monkeypatch):
        monkeypatch.setattr(
            "app.scanner.validator.resolve_hostname_safely",
            lambda host: "93.184.216.34",
        )
        norm_url, hostname, ip = validate_and_normalize_url("example.com/profile")
        assert norm_url.startswith("https://")
        assert hostname == "example.com"

    def test_rejects_non_https_scheme(self):
        with pytest.raises(SecurityValidationError, match="requires HTTPS"):
            validate_and_normalize_url("http://example.com")

        with pytest.raises(SecurityValidationError, match="requires HTTPS"):
            validate_and_normalize_url("ftp://example.com")

        with pytest.raises(SecurityValidationError, match="requires HTTPS"):
            validate_and_normalize_url("file:///etc/passwd")

    def test_rejects_embedded_credentials(self):
        with pytest.raises(SecurityValidationError, match="User credentials embedded"):
            validate_and_normalize_url("https://admin:secret@example.com")

    def test_rejects_disallowed_hostnames(self):
        disallowed = [
            "localhost",
            "metadata.google.internal",
            "kubernetes.default",
            "server.local",
            "gateway.internal",
            "cluster.lan",
        ]
        for host in disallowed:
            with pytest.raises(SecurityValidationError):
                validate_and_normalize_url(f"https://{host}/")

    def test_rejects_private_ip_literals(self):
        with pytest.raises(SecurityValidationError, match="SSRF blocked"):
            validate_and_normalize_url("https://127.0.0.1/admin")

        with pytest.raises(SecurityValidationError, match="SSRF blocked"):
            validate_and_normalize_url("https://169.254.169.254/latest/meta-data/")

        with pytest.raises(SecurityValidationError, match="SSRF blocked"):
            validate_and_normalize_url("https://192.168.0.1/")

    def test_rejects_disallowed_ports(self, monkeypatch):
        monkeypatch.setattr(
            "app.scanner.validator.resolve_hostname_safely",
            lambda host: "93.184.216.34",
        )
        with pytest.raises(SecurityValidationError, match="Port 8080 is not permitted"):
            validate_and_normalize_url("https://example.com:8080/", allowed_ports=[443])

    def test_rejects_empty_and_invalid_urls(self):
        with pytest.raises(SecurityValidationError):
            validate_and_normalize_url("")

        with pytest.raises(SecurityValidationError):
            validate_and_normalize_url("   ")
