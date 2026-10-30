#!/usr/bin/env python3
"""Clickjacking Detection Engine

Standalone defensive cybersecurity module for detecting and analyzing
anti-framing mechanisms (X-Frame-Options and Content-Security-Policy
frame-ancestors) against Clickjacking (UI Redressing) attacks.

Features:
- RFC 7034 & W3C CSP Level 3 compliant analysis
- SSRF-safe HTTP header retrieval
- Comprehensive directive parsing (DENY, SAMEORIGIN, frame-ancestors 'none'/'self'/hosts)
- Conflict and misconfiguration detection (unquoted keywords, wildcards, duplicates)
- Standalone CLI with formatted colorized reports and JSON output

Usage:
    CLI:
        python detector.py https://example.com
        python detector.py https://example.com --json

    Python API:
        from clickjacking_detection import ClickjackDetector, detect_clickjacking

        result = detect_clickjacking("https://example.com")
        print(result["outcome"])  # 'Protected' | 'Potential Risk' | 'Inconclusive'
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False


# ANSI Terminal Colors
class Colors:
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    PURPLE = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


class SecurityValidationError(Exception):
    """Raised when URL or target IP fails security validation."""
    pass


class ClickjackDetector:
    """Core Clickjacking Detection and Analysis Engine."""

    DISALLOWED_IP_RANGES = [
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.0.0.0/24"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("198.18.0.0/15"),
        ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    USER_AGENT = "ClickjackShield-Detection-Tool/1.0 (+Defensive Security Audit)"

    def __init__(self, timeout: int = 8, allow_private_ips: bool = False):
        self.timeout = timeout
        self.allow_private_ips = allow_private_ips

    def validate_url(self, url: str) -> Tuple[str, str, str]:
        """Validates the input URL and ensures it does not resolve to private/internal IPs (SSRF defense)."""
        raw_url = url.strip()
        if not raw_url:
            raise SecurityValidationError("Target URL cannot be empty.")

        if not raw_url.startswith(("http://", "https://")):
            raw_url = "https://" + raw_url

        parsed = urlparse(raw_url)
        hostname = parsed.hostname or ""
        scheme = parsed.scheme.lower()

        if scheme not in ("http", "https"):
            raise SecurityValidationError(f"Unsupported scheme: {scheme}. Use HTTPS or HTTP.")

        if not hostname:
            raise SecurityValidationError(f"Invalid URL: could not parse hostname from '{url}'.")

        # Resolve IP and check SSRF boundaries if private IPs are restricted
        resolved_ip = "Unknown"
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            resolved_ips = [info[4][0] for info in addr_info]
            if resolved_ips:
                resolved_ip = resolved_ips[0]

            if not self.allow_private_ips and resolved_ip != "Unknown":
                ip_obj = ipaddress.ip_address(resolved_ip)
                for block in self.DISALLOWED_IP_RANGES:
                    if ip_obj in block:
                        raise SecurityValidationError(
                            f"Target resolves to restricted internal/private IP: {resolved_ip} (SSRF Defense)."
                        )
        except socket.gaierror as e:
            raise SecurityValidationError(f"Could not resolve domain '{hostname}': {e}")

        return raw_url, hostname, resolved_ip

    def fetch_headers(self, url: str) -> Dict[str, Any]:
        """Safely fetches HTTP response headers for the given URL."""
        validated_url, hostname, resolved_ip = self.validate_url(url)

        if HAS_REQUESTS:
            try:
                session = requests.Session()
                session.headers.update({"User-Agent": self.USER_AGENT})
                resp = session.get(
                    validated_url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    stream=True,  # stream avoids reading large body
                )
                headers = {k.lower(): v for k, v in resp.headers.items()}
                status_code = resp.status_code
                final_url = resp.url
                # Read at most 10KB then close
                resp.close()
            except requests.exceptions.RequestException as e:
                return {
                    "url": validated_url,
                    "final_url": validated_url,
                    "hostname": hostname,
                    "ip_address": resolved_ip,
                    "status_code": None,
                    "headers": {},
                    "error": str(e),
                }
        else:
            try:
                req = urllib.request.Request(validated_url, headers={"User-Agent": self.USER_AGENT})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    status_code = resp.getcode()
                    final_url = resp.geturl()
            except urllib.error.HTTPError as e:
                headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
                status_code = e.code
                final_url = validated_url
            except Exception as e:
                return {
                    "url": validated_url,
                    "final_url": validated_url,
                    "hostname": hostname,
                    "ip_address": resolved_ip,
                    "status_code": None,
                    "headers": {},
                    "error": str(e),
                }

        return {
            "url": validated_url,
            "final_url": final_url,
            "hostname": hostname,
            "ip_address": resolved_ip,
            "status_code": status_code,
            "headers": headers,
            "error": None,
        }

    def analyze(self, url: str) -> Dict[str, Any]:
        """Runs complete detection against target URL and returns structured evaluation."""
        fetch_result = self.fetch_headers(url)
        if fetch_result.get("error") or not fetch_result.get("status_code"):
            return {
                "url": fetch_result["url"],
                "final_url": fetch_result.get("final_url", url),
                "hostname": fetch_result.get("hostname", "Unknown"),
                "ip_address": fetch_result.get("ip_address", "Unknown"),
                "http_status": fetch_result.get("status_code"),
                "outcome": "Inconclusive",
                "confidence": "Low",
                "explanation": f"Network error during connection: {fetch_result.get('error')}",
                "remediation": "Verify the website is online, accessible via public HTTPS, and accepting connections.",
                "xfo_present": False,
                "xfo_status": "Unreachable",
                "xfo_raw": None,
                "csp_present": False,
                "csp_status": "Unreachable",
                "csp_frame_ancestors": None,
                "findings": ["Failed to establish HTTP connection with target."],
            }

        headers = fetch_result["headers"]
        status_code = fetch_result["status_code"]
        final_url = fetch_result["final_url"]
        hostname = fetch_result["hostname"]
        ip_addr = fetch_result["ip_address"]

        findings = []

        # ── 1. Evaluate X-Frame-Options ──
        raw_xfo = headers.get("x-frame-options")
        xfo_analysis = self._evaluate_xfo(raw_xfo)
        findings.extend(xfo_analysis["findings"])

        # ── 2. Evaluate CSP frame-ancestors ──
        raw_csp = headers.get("content-security-policy")
        raw_csp_ro = headers.get("content-security-policy-report-only")
        csp_analysis = self._evaluate_csp(raw_csp, raw_csp_ro)
        findings.extend(csp_analysis["findings"])

        # ── 3. Synthesize Overall Posture ──
        outcome, confidence, explanation, remediation = self._synthesize_posture(
            xfo_analysis, csp_analysis, status_code
        )

        return {
            "url": fetch_result["url"],
            "final_url": final_url,
            "hostname": hostname,
            "ip_address": ip_addr,
            "http_status": status_code,
            "outcome": outcome,
            "confidence": confidence,
            "explanation": explanation,
            "remediation": remediation,
            "xfo_present": xfo_analysis["present"],
            "xfo_raw": raw_xfo,
            "xfo_status": xfo_analysis["status"],
            "xfo_details": xfo_analysis["details"],
            "csp_present": csp_analysis["present"],
            "csp_raw": raw_csp,
            "csp_frame_ancestors": csp_analysis["frame_ancestors_raw"],
            "csp_status": csp_analysis["status"],
            "csp_details": csp_analysis["details"],
            "findings": findings,
            "headers_inspected": {
                "x-frame-options": raw_xfo,
                "content-security-policy": raw_csp,
                "strict-transport-security": headers.get("strict-transport-security"),
                "x-content-type-options": headers.get("x-content-type-options"),
                "referrer-policy": headers.get("referrer-policy"),
            },
        }

    def _evaluate_xfo(self, raw_xfo: Optional[str]) -> Dict[str, Any]:
        """Inspects X-Frame-Options header values according to RFC 7034."""
        if not raw_xfo:
            return {
                "present": False,
                "status": "Missing",
                "details": "Header absent. Page can be embedded in iframes unless protected by CSP.",
                "directive": None,
                "findings": ["X-Frame-Options header is NOT configured."],
            }

        val = raw_xfo.strip()
        upper = val.upper()
        findings = [f"X-Frame-Options header detected: '{val}'"]

        if upper == "DENY":
            return {
                "present": True,
                "status": "Protected (DENY)",
                "details": "Completely prohibits framing in all compliant browsers.",
                "directive": "DENY",
                "findings": findings + ["X-Frame-Options: DENY is valid and securely blocks all framing."],
            }
        elif upper == "SAMEORIGIN":
            return {
                "present": True,
                "status": "Protected (SAMEORIGIN)",
                "details": "Allows framing only by parent pages sharing the identical origin.",
                "directive": "SAMEORIGIN",
                "findings": findings + ["X-Frame-Options: SAMEORIGIN is valid and limits framing to same origin."],
            }
        elif upper.startswith("ALLOW-FROM"):
            return {
                "present": True,
                "status": "Potential Risk (Deprecated ALLOW-FROM)",
                "details": "ALLOW-FROM is deprecated and ignored in modern browsers (Chrome, Safari, Edge).",
                "directive": "ALLOW-FROM",
                "findings": findings + ["WARNING: 'ALLOW-FROM' is deprecated and ignored by modern browsers."],
            }
        elif "," in val:
            return {
                "present": True,
                "status": "Potential Risk (Duplicate/Conflicting)",
                "details": f"Multiple or comma-separated directives detected: '{val}'.",
                "directive": "CONFLICT",
                "findings": findings + ["WARNING: Conflicting multiple XFO directives detected."],
            }
        else:
            return {
                "present": True,
                "status": "Potential Risk (Invalid Directive)",
                "details": f"Unrecognized directive '{val}'. Browsers ignore invalid X-Frame-Options values.",
                "directive": "INVALID",
                "findings": findings + [f"WARNING: Invalid X-Frame-Options directive '{val}'."],
            }

    def _evaluate_csp(self, raw_csp: Optional[str], raw_csp_ro: Optional[str]) -> Dict[str, Any]:
        """Inspects Content-Security-Policy for frame-ancestors directive."""
        if not raw_csp:
            if raw_csp_ro and "frame-ancestors" in raw_csp_ro:
                return {
                    "present": False,
                    "frame_ancestors_raw": None,
                    "status": "Potential Risk (Report-Only)",
                    "details": "frame-ancestors defined in Content-Security-Policy-Report-Only (monitored, not enforced).",
                    "findings": ["CSP frame-ancestors is present in Report-Only mode (not actively blocking framing)."],
                }
            return {
                "present": False,
                "frame_ancestors_raw": None,
                "status": "Missing",
                "details": "Content-Security-Policy header or frame-ancestors directive absent.",
                "findings": ["Content-Security-Policy: frame-ancestors is NOT configured."],
            }

        # Parse directives split by ';'
        directives = [d.strip() for d in raw_csp.split(";") if d.strip()]
        fa_match = None
        for d in directives:
            if d.lower().startswith("frame-ancestors"):
                fa_match = d
                break

        if not fa_match:
            return {
                "present": False,
                "frame_ancestors_raw": None,
                "status": "Missing Directive",
                "details": "CSP is set, but frame-ancestors directive is missing (default-src does NOT restrict framing).",
                "findings": ["CSP header exists, but lacks the 'frame-ancestors' directive."],
            }

        findings = [f"CSP frame-ancestors detected: '{fa_match}'"]
        tokens = fa_match.split()[1:]  # tokens after 'frame-ancestors'

        if not tokens:
            return {
                "present": True,
                "frame_ancestors_raw": fa_match,
                "status": "Potential Risk (Empty Directive)",
                "details": "frame-ancestors directive has no sources defined.",
                "findings": findings + ["WARNING: frame-ancestors directive is empty."],
            }

        token_lower = [t.lower() for t in tokens]

        if "'none'" in token_lower:
            return {
                "present": True,
                "frame_ancestors_raw": fa_match,
                "status": "Protected (none)",
                "details": "frame-ancestors 'none' forbids all parent framing across modern browsers.",
                "findings": findings + ["CSP frame-ancestors 'none' securely disallows all embedding."],
            }
        elif "'self'" in token_lower and len(tokens) == 1:
            return {
                "present": True,
                "frame_ancestors_raw": fa_match,
                "status": "Protected (self)",
                "details": "frame-ancestors 'self' limits framing strictly to same-origin parents.",
                "findings": findings + ["CSP frame-ancestors 'self' restricts framing to own origin."],
            }
        elif "*" in tokens:
            return {
                "present": True,
                "frame_ancestors_raw": fa_match,
                "status": "Potential Risk (Wildcard)",
                "details": "Wildcard '*' allows ANY website to frame this application without restriction.",
                "findings": findings + ["WARNING: Wildcard '*' allows any domain to frame this page."],
            }
        elif "none" in token_lower or "self" in token_lower:
            # Unquoted keyword misconfiguration: self instead of 'self'
            return {
                "present": True,
                "frame_ancestors_raw": fa_match,
                "status": "Potential Risk (Unquoted Keywords)",
                "details": "Keywords self or none must be surrounded by single quotes ('self', 'none').",
                "findings": findings + ["WARNING: Keywords must be single-quoted ('self' / 'none')."],
            }
        else:
            sources_str = ", ".join(tokens)
            return {
                "present": True,
                "frame_ancestors_raw": fa_match,
                "status": "Protected (Whitelisted Origins)",
                "details": f"Framing authorized for specific sources: {sources_str}.",
                "findings": findings + [f"CSP frame-ancestors restricts framing to whitelisted hosts: {sources_str}."],
            }

    def _synthesize_posture(
        self, xfo: Dict[str, Any], csp: Dict[str, Any], status: int
    ) -> Tuple[str, str, str, str]:
        """Combines findings into final security posture (Protected / Potential Risk / Inconclusive)."""
        xfo_ok = xfo["status"].startswith("Protected")
        csp_ok = csp["status"].startswith("Protected")

        if csp_ok and xfo_ok:
            return (
                "Protected",
                "High",
                "Comprehensive defense enforced: both CSP frame-ancestors and X-Frame-Options are configured correctly.",
                "Maintain current security headers in continuous deployment pipelines.",
            )
        elif csp_ok:
            return (
                "Protected",
                "High",
                "Modern standard enforced: CSP frame-ancestors actively blocks framing. Modern browsers honor this directive.",
                "Consider also adding 'X-Frame-Options: DENY' for legacy user agents that do not support CSP Level 2.",
            )
        elif xfo_ok:
            return (
                "Protected",
                "Medium",
                f"Legacy protection active via {xfo['status']}. Compliant browsers will respect this header.",
                "Upgrade to modern Content-Security-Policy with 'frame-ancestors' directive for granular multi-domain controls.",
            )
        else:
            return (
                "Potential Risk",
                "High",
                "Missing or weak anti-framing defenses: Neither X-Frame-Options nor CSP frame-ancestors is effectively configured.",
                "Implement 'Content-Security-Policy: frame-ancestors \'none\';' and 'X-Frame-Options: DENY' immediately.",
            )


def detect_clickjacking(url: str, allow_private_ips: bool = False) -> Dict[str, Any]:
    """Convenience function to inspect a target URL for Clickjacking defenses."""
    detector = ClickjackDetector(allow_private_ips=allow_private_ips)
    return detector.analyze(url)


def print_cli_report(res: Dict[str, Any]) -> None:
    """Prints a formatted, colorized security report to stdout."""
    outcome = res["outcome"]
    if outcome == "Protected":
        outcome_color = Colors.GREEN
        badge = "[✓ PROTECTED]"
    elif outcome == "Potential Risk":
        outcome_color = Colors.YELLOW
        badge = "[! POTENTIAL RISK]"
    else:
        outcome_color = Colors.RED
        badge = "[? INCONCLUSIVE]"

    print("\n" + "=" * 70)
    print(f" {Colors.BOLD}CLICKJACKING DEFENSE ASSESSMENT REPORT{Colors.RESET}")
    print("=" * 70)
    print(f" Target URL:        {Colors.CYAN}{res['url']}{Colors.RESET}")
    print(f" Final Destination: {res['final_url']}")
    print(f" Hostname / IP:     {res['hostname']} ({res['ip_address']})")
    print(f" HTTP Status:       {res['http_status'] or 'N/A'}")
    print(f" Overall Posture:   {outcome_color}{Colors.BOLD}{badge} ({res['confidence']} Confidence){Colors.RESET}")
    print("-" * 70)

    print(f"{Colors.BOLD}Header Analysis:{Colors.RESET}")
    xfo_stat = res["xfo_status"]
    xfo_color = Colors.GREEN if "Protected" in xfo_stat else Colors.YELLOW
    print(f"  • X-Frame-Options:        {xfo_color}{xfo_stat}{Colors.RESET}")
    if res["xfo_raw"]:
        print(f"    Raw Value:             {Colors.DIM}{res['xfo_raw']}{Colors.RESET}")
    print(f"    Details:               {res['xfo_details']}")

    csp_stat = res["csp_status"]
    csp_color = Colors.GREEN if "Protected" in csp_stat else Colors.YELLOW
    print(f"  • CSP frame-ancestors:    {csp_color}{csp_stat}{Colors.RESET}")
    if res["csp_frame_ancestors"]:
        print(f"    Raw Directive:         {Colors.DIM}{res['csp_frame_ancestors']}{Colors.RESET}")
    print(f"    Details:               {res['csp_details']}")

    print("-" * 70)
    print(f"{Colors.BOLD}Summary Explanation:{Colors.RESET}")
    print(f"  {res['explanation']}")

    print(f"\n{Colors.BOLD}Recommended Remediation:{Colors.RESET}")
    print(f"  {Colors.CYAN}{res['remediation']}{Colors.RESET}")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Clickjacking Detection Tool: Evaluate HTTP security headers against UI redressing attacks."
    )
    parser.add_argument("url", help="Target website URL to evaluate (e.g. https://example.com)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON results")
    parser.add_argument("--allow-private", action="store_true", help="Allow scanning internal/private IP ranges (SSRF bypass)")
    parser.add_argument("--timeout", type=int, default=8, help="Connection timeout in seconds (default: 8)")

    args = parser.parse_args()

    detector = ClickjackDetector(timeout=args.timeout, allow_private_ips=args.allow_private)
    try:
        results = detector.analyze(args.url)
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print_cli_report(results)
            # Exit code: 0 if Protected, 1 if Potential Risk, 2 if Inconclusive
            if results["outcome"] == "Protected":
                sys.exit(0)
            elif results["outcome"] == "Potential Risk":
                sys.exit(1)
            else:
                sys.exit(2)
    except SecurityValidationError as e:
        print(f"\n{Colors.RED}[!] Security Validation Error:{Colors.RESET} {e}\n", file=sys.stderr)
        sys.exit(3)
    except Exception as e:
        print(f"\n{Colors.RED}[!] Unexpected Error:{Colors.RESET} {e}\n", file=sys.stderr)
        sys.exit(4)


if __name__ == "__main__":
    main()
