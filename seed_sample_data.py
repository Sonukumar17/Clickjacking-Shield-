"""Sample Data Seeding Script

Pre-populates the local SQLite database with realistic assessment records
demonstrating Protected, Potential Risk, and Inconclusive postures.
"""

from app.models import AssessmentRepository
from config import Config


def seed():
    repo = AssessmentRepository(Config.DATABASE_PATH)
    print(f"[*] Initializing sample assessments in {Config.DATABASE_PATH}...")

    samples = [
        {
            "id": "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d",
            "url": "https://github.com",
            "final_url": "https://github.com/",
            "hostname": "github.com",
            "ip_address": "140.82.112.4",
            "scan_timestamp": "2026-10-30T16:45:00Z",
            "http_status": 200,
            "outcome": "Protected",
            "confidence": "High",
            "xfo_present": True,
            "xfo_raw": "deny",
            "xfo_status": "Protected (DENY)",
            "xfo_details": "Configured with DENY. Modern and legacy browsers will refuse framing anywhere.",
            "csp_present": True,
            "csp_raw": "default-src 'none'; frame-ancestors 'none';",
            "csp_frame_ancestors": "frame-ancestors 'none'",
            "csp_status": "Protected (frame-ancestors 'none')",
            "csp_details": "Configured with 'none'. Browser will refuse to embed the resource into any frame.",
            "other_headers": {
                "strict_transport_security": {"present": True, "value": "max-age=31536000; includeSubdomains; preload"},
                "x_content_type_options": {"present": True, "value": "nosniff"},
                "samesite_cookie": {"present": True, "value": "Lax"},
            },
            "redirects": [],
            "explanation": "Target application implements recognized anti-framing protections. Multi-layer defense active.",
            "remediation": "Robust protection is in place. Maintain CI/CD automated header assertions.",
        },
        {
            "id": "b2c3d4e5-f6a1-4b2c-9d3e-4f5a6b7c8d9e",
            "url": "https://google.com",
            "final_url": "https://www.google.com/",
            "hostname": "google.com",
            "ip_address": "142.250.190.46",
            "scan_timestamp": "2026-10-30T17:10:00Z",
            "http_status": 200,
            "outcome": "Protected",
            "confidence": "High",
            "xfo_present": True,
            "xfo_raw": "SAMEORIGIN",
            "xfo_status": "Protected (SAMEORIGIN)",
            "xfo_details": "Configured with 'SAMEORIGIN'. Framing permitted exclusively from same origin.",
            "csp_present": False,
            "csp_raw": None,
            "csp_frame_ancestors": None,
            "csp_status": "Missing",
            "csp_details": "No Content-Security-Policy header returned.",
            "other_headers": {
                "strict_transport_security": {"present": True, "value": "max-age=31536000"},
                "x_content_type_options": {"present": True, "value": "nosniff"},
                "samesite_cookie": {"present": True, "value": "Lax"},
            },
            "redirects": [
                {"hop": 1, "from": "https://google.com", "to": "https://www.google.com/", "status_code": 301}
            ],
            "explanation": "Target application enforces X-Frame-Options: SAMEORIGIN, successfully blocking cross-origin framing.",
            "remediation": "Consider adding Content-Security-Policy: frame-ancestors 'self' for modern CSP compliance.",
        },
        {
            "id": "c3d4e5f6-a1b2-4c3d-ae4f-5a6b7c8d9e0f",
            "url": "https://legacy-portal.internal-audit.demo",
            "final_url": "https://legacy-portal.internal-audit.demo/",
            "hostname": "legacy-portal.internal-audit.demo",
            "ip_address": "198.51.100.45",
            "scan_timestamp": "2026-10-30T17:30:00Z",
            "http_status": 200,
            "outcome": "Potential Risk",
            "confidence": "Medium",
            "xfo_present": False,
            "xfo_raw": None,
            "xfo_status": "Missing",
            "xfo_details": "No X-Frame-Options header was returned by the server.",
            "csp_present": False,
            "csp_raw": None,
            "csp_frame_ancestors": None,
            "csp_status": "Missing",
            "csp_details": "No Content-Security-Policy header was returned.",
            "other_headers": {
                "strict_transport_security": {"present": False, "value": None},
                "x_content_type_options": {"present": False, "value": None},
                "samesite_cookie": {"present": False, "value": None},
            },
            "redirects": [],
            "explanation": "No recognized anti-framing restrictions were identified. While this indicates a potential security misconfiguration, exploitability requires a sensitive authenticated state.",
            "remediation": "Add 'Content-Security-Policy: frame-ancestors \'none\';' and 'X-Frame-Options: DENY' to server configuration.",
        },
        {
            "id": "d4e5f6a1-b2c3-4d4e-bf5a-6b7c8d9e0f1a",
            "url": "https://permissive-partner.audit.demo",
            "final_url": "https://permissive-partner.audit.demo/",
            "hostname": "permissive-partner.audit.demo",
            "ip_address": "203.0.113.12",
            "scan_timestamp": "2026-10-30T17:42:00Z",
            "http_status": 200,
            "outcome": "Potential Risk",
            "confidence": "High",
            "xfo_present": False,
            "xfo_raw": None,
            "xfo_status": "Missing",
            "xfo_details": "No XFO header returned.",
            "csp_present": True,
            "csp_raw": "frame-ancestors *;",
            "csp_frame_ancestors": "frame-ancestors *",
            "csp_status": "Permissive (Wildcard *)",
            "csp_details": "The 'frame-ancestors' directive contains a wildcard ('*'), explicitly permitting any website to embed the app.",
            "other_headers": {
                "strict_transport_security": {"present": True, "value": "max-age=31536000"},
                "x_content_type_options": {"present": True, "value": "nosniff"},
            },
            "redirects": [],
            "explanation": "Permissive wildcard frame-ancestors directive disables browser framing protections.",
            "remediation": "Replace wildcard '*' with specific whitelisted origin domains or 'self'.",
        },
        {
            "id": "e5f6a1b2-c3d4-4e5f-c01a-7b8c9d0e1f2b",
            "url": "https://offline-gateway.audit.demo",
            "final_url": "https://offline-gateway.audit.demo/",
            "hostname": "offline-gateway.audit.demo",
            "ip_address": "198.51.100.99",
            "scan_timestamp": "2026-10-30T17:50:00Z",
            "http_status": 503,
            "outcome": "Inconclusive",
            "confidence": "Low",
            "xfo_present": False,
            "xfo_raw": None,
            "xfo_status": "Inconclusive",
            "xfo_details": "Response not evaluable.",
            "csp_present": False,
            "csp_raw": None,
            "csp_frame_ancestors": None,
            "csp_status": "Inconclusive",
            "csp_details": "Response not evaluable.",
            "other_headers": {},
            "redirects": [],
            "explanation": "Target server returned HTTP 503 Service Unavailable. Assessment could not be conclusively determined.",
            "remediation": "Ensure target service is healthy and returning HTTP 200 before assessing headers.",
        },
    ]

    for item in samples:
        repo.save(item)
        print(f" [+] Inserted sample assessment: {item['hostname']} ({item['outcome']})")

    stats = repo.get_statistics()
    print(f"[+] Seeding complete! Database has {stats['total']} total records.")


if __name__ == "__main__":
    seed()
