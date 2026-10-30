"""Clickjacking Security Header Analyzer Module

Performs comprehensive evaluation of HTTP response headers according to
RFC 7034, W3C Content Security Policy Level 2/3, and OWASP Clickjacking Defense Cheat Sheet.
Accurately assesses X-Frame-Options, CSP frame-ancestors, conflicts, and defense-in-depth headers.
"""

import re
from typing import Any, Dict, List, Optional, Tuple


class SecurityAnalyzer:
    """Evaluates HTTP response headers for anti-framing mechanisms and misconfigurations."""

    @classmethod
    def analyze_headers(
        cls,
        headers: Dict[str, str],
        http_status: Optional[int],
        url: str,
        final_url: str,
    ) -> Dict[str, Any]:
        """Analyzes headers dictionary and produces structured findings and outcome status.

        Args:
            headers: Dict of HTTP response headers (case-insensitive lowercased keys).
            http_status: HTTP status code received.
            url: Initial target URL.
            final_url: Final destination URL after redirects.

        Returns:
            Dict containing detailed evaluation, parsed directives, risk assessment,
            explanations, and remediation recommendations.
        """
        # If response was an error or empty
        if not http_status or http_status >= 400:
            return cls._handle_inconclusive(
                headers=headers,
                http_status=http_status,
                url=url,
                final_url=final_url,
                reason=f"Target server returned HTTP status code {http_status or 'Unknown'}. Assessment inconclusive.",
            )

        # 1. Analyze X-Frame-Options
        xfo_analysis = cls._analyze_x_frame_options(headers.get("x-frame-options"))

        # 2. Analyze Content-Security-Policy (and Report-Only)
        csp_analysis = cls._analyze_csp(
            headers.get("content-security-policy"),
            headers.get("content-security-policy-report-only"),
        )

        # 3. Analyze Secondary Defense Headers
        secondary_headers = cls._analyze_secondary_headers(headers)

        # 4. Synthesize Anti-Framing Outcome and Confidence
        outcome, confidence, explanation, remediation = cls._evaluate_overall_posture(
            xfo=xfo_analysis,
            csp=csp_analysis,
            secondary=secondary_headers,
            http_status=http_status,
        )

        return {
            "url": url,
            "final_url": final_url,
            "http_status": http_status,
            "outcome": outcome,
            "confidence": confidence,
            "explanation": explanation,
            "remediation": remediation,
            "xfo_present": xfo_analysis["present"],
            "xfo_raw": xfo_analysis["raw"],
            "xfo_status": xfo_analysis["status"],
            "xfo_details": xfo_analysis["details"],
            "xfo_directive": xfo_analysis.get("directive"),
            "csp_present": csp_analysis["present"],
            "csp_raw": csp_analysis["raw"],
            "csp_frame_ancestors": csp_analysis.get("frame_ancestors_raw"),
            "csp_status": csp_analysis["status"],
            "csp_details": csp_analysis["details"],
            "csp_sources": csp_analysis.get("sources", []),
            "other_headers": secondary_headers,
            "precedence_note": cls._determine_precedence_note(xfo_analysis, csp_analysis),
        }

    @classmethod
    def _analyze_x_frame_options(cls, raw_val: Optional[str]) -> Dict[str, Any]:
        """Analyzes the X-Frame-Options header value."""
        if not raw_val:
            return {
                "present": False,
                "raw": None,
                "status": "Missing",
                "directive": None,
                "is_effective": False,
                "details": "No X-Frame-Options header was returned by the server.",
            }

        cleaned = raw_val.strip()
        upper = cleaned.upper()

        # Check for multiple comma-separated values (often a web server misconfiguration)
        if "," in cleaned:
            parts = [p.strip().upper() for p in cleaned.split(",")]
            unique_parts = list(set(parts))
            if len(unique_parts) > 1:
                return {
                    "present": True,
                    "raw": cleaned,
                    "status": "Conflicting / Malformed",
                    "directive": cleaned,
                    "is_effective": False,
                    "details": (
                        f"Multiple conflicting X-Frame-Options values detected: [{', '.join(parts)}]. "
                        "Browsers may reject ambiguous duplicate headers, leaving the application unprotected."
                    ),
                }
            upper = unique_parts[0]

        if upper == "DENY":
            return {
                "present": True,
                "raw": cleaned,
                "status": "Protected (DENY)",
                "directive": "DENY",
                "is_effective": True,
                "details": (
                    "Configured with 'DENY'. Modern and legacy browsers will strictly refuse to display "
                    "this page within any frame or iframe regardless of origin."
                ),
            }

        if upper == "SAMEORIGIN":
            return {
                "present": True,
                "raw": cleaned,
                "status": "Protected (SAMEORIGIN)",
                "directive": "SAMEORIGIN",
                "is_effective": True,
                "details": (
                    "Configured with 'SAMEORIGIN'. The browser permits framing only if the top-level origin "
                    "matches the origin of the framed content."
                ),
            }

        if upper.startswith("ALLOW-FROM"):
            return {
                "present": True,
                "raw": cleaned,
                "status": "Deprecated (ALLOW-FROM)",
                "directive": "ALLOW-FROM",
                "is_effective": False,
                "details": (
                    "Configured with 'ALLOW-FROM'. This directive is obsolete (RFC 7034) and is ignored "
                    "by Chrome, Safari, and modern browsers. Use Content-Security-Policy frame-ancestors instead."
                ),
            }

        # Any other value is invalid / malformed
        return {
            "present": True,
            "raw": cleaned,
            "status": "Invalid / Non-Standard",
            "directive": cleaned,
            "is_effective": False,
            "details": (
                f"Unrecognized X-Frame-Options value: '{cleaned}'. "
                "Browsers fail open on invalid directives, providing zero clickjacking protection."
            ),
        }

    @classmethod
    def _analyze_csp(cls, raw_csp: Optional[str], raw_ro_csp: Optional[str] = None) -> Dict[str, Any]:
        """Analyzes Content-Security-Policy for the frame-ancestors directive."""
        if not raw_csp:
            details = "No Content-Security-Policy header was returned."
            if raw_ro_csp and "frame-ancestors" in raw_ro_csp.lower():
                details += (
                    " Note: 'Content-Security-Policy-Report-Only' was detected with frame-ancestors, "
                    "but report-only mode does not enforce blocking in browsers."
                )
            return {
                "present": False,
                "raw": None,
                "frame_ancestors_raw": None,
                "status": "Missing",
                "sources": [],
                "is_effective": False,
                "details": details,
            }

        # Parse directives split by ';'
        directives = [d.strip() for d in raw_csp.split(";") if d.strip()]
        fa_directives = []

        for d in directives:
            parts = d.split()
            if not parts:
                continue
            name = parts[0].lower()
            if name == "frame-ancestors":
                fa_directives.append(parts[1:])

        if not fa_directives:
            return {
                "present": True,
                "raw": raw_csp,
                "frame_ancestors_raw": None,
                "status": "Missing frame-ancestors Directive",
                "sources": [],
                "is_effective": False,
                "details": (
                    "Content-Security-Policy is present, but lacks the 'frame-ancestors' directive. "
                    "Other directives (e.g. script-src, frame-src) do NOT protect against being framed."
                ),
            }

        # If multiple frame-ancestors directives exist
        if len(fa_directives) > 1:
            return {
                "present": True,
                "raw": raw_csp,
                "frame_ancestors_raw": "; ".join(
                    ["frame-ancestors " + " ".join(f) for f in fa_directives]
                ),
                "status": "Malformed (Duplicate Directives)",
                "sources": [s for sub in fa_directives for s in sub],
                "is_effective": False,
                "details": (
                    "Multiple 'frame-ancestors' directives defined in a single CSP header. "
                    "According to CSP specification, duplicate directives cause parser conflicts."
                ),
            }

        sources = fa_directives[0]
        fa_str = "frame-ancestors " + " ".join(sources)

        if not sources:
            return {
                "present": True,
                "raw": raw_csp,
                "frame_ancestors_raw": fa_str,
                "status": "Malformed (Empty Sources)",
                "sources": [],
                "is_effective": False,
                "details": "The 'frame-ancestors' directive is present but has no sources specified.",
            }

        # Check for unquoted 'none' or 'self' (common misconfiguration)
        unquoted_keywords = [s for s in sources if s.lower() in ("none", "self")]
        if unquoted_keywords:
            return {
                "present": True,
                "raw": raw_csp,
                "frame_ancestors_raw": fa_str,
                "status": "Misconfigured (Unquoted Keywords)",
                "sources": sources,
                "is_effective": False,
                "details": (
                    f"Keywords {unquoted_keywords} are missing single quotes! "
                    "In CSP, unquoted keywords are treated as hostnames, leaving framing unrestricted."
                ),
            }

        # Check for wildcard '*' or overly broad sources
        if "'*'" in sources or "*" in sources:
            return {
                "present": True,
                "raw": raw_csp,
                "frame_ancestors_raw": fa_str,
                "status": "Permissive (Wildcard *)",
                "sources": sources,
                "is_effective": False,
                "details": (
                    "The 'frame-ancestors' directive contains a wildcard ('*'). "
                    "This explicitly permits any website on the internet to embed this application."
                ),
            }

        # Check for strong 'none'
        if "'none'" in [s.lower() for s in sources]:
            return {
                "present": True,
                "raw": raw_csp,
                "frame_ancestors_raw": fa_str,
                "status": "Protected (frame-ancestors 'none')",
                "sources": sources,
                "is_effective": True,
                "details": (
                    "Configured with 'none'. The browser will refuse to embed the resource "
                    "into any frame or iframe anywhere, providing maximum clickjacking defense."
                ),
            }

        # Check for 'self'
        if "'self'" in [s.lower() for s in sources]:
            other_hosts = [s for s in sources if s.lower() != "'self'"]
            if other_hosts:
                details = f"Configured with 'self' and authorized external origins: [{', '.join(other_hosts)}]."
            else:
                details = "Configured with 'self'. Framing is restricted exclusively to the same origin."
            return {
                "present": True,
                "raw": raw_csp,
                "frame_ancestors_raw": fa_str,
                "status": "Protected (Restricted Origins)",
                "sources": sources,
                "is_effective": True,
                "details": details,
            }

        # Specific whitelist of origins
        return {
            "present": True,
            "raw": raw_csp,
            "frame_ancestors_raw": fa_str,
            "status": "Protected (Whitelisted Origins)",
            "sources": sources,
            "is_effective": True,
            "details": f"Framing is restricted to specific trusted origins: [{', '.join(sources)}].",
        }

    @classmethod
    def _analyze_secondary_headers(cls, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyzes complementary defense-in-depth headers."""
        hsts = headers.get("strict-transport-security")
        xcto = headers.get("x-content-type-options")
        referrer = headers.get("referrer-policy")
        permissions = headers.get("permissions-policy")
        server = headers.get("server")
        x_powered_by = headers.get("x-powered-by")
        set_cookie = headers.get("set-cookie")

        # Check for SameSite attribute in Set-Cookie (mitigates authenticated clickjacking)
        samesite_found = None
        if set_cookie:
            sc_lower = set_cookie.lower()
            if "samesite=strict" in sc_lower:
                samesite_found = "Strict"
            elif "samesite=lax" in sc_lower:
                samesite_found = "Lax"
            elif "samesite=none" in sc_lower:
                samesite_found = "None"

        return {
            "strict_transport_security": {
                "present": bool(hsts),
                "value": hsts,
                "description": "Enforces HTTPS and defends against SSL-stripping man-in-the-middle attacks.",
            },
            "x_content_type_options": {
                "present": bool(xcto),
                "value": xcto,
                "description": "Prevents MIME-type sniffing by browsers (expected: 'nosniff').",
            },
            "referrer_policy": {
                "present": bool(referrer),
                "value": referrer,
                "description": "Controls how much referrer information is included with requests.",
            },
            "permissions_policy": {
                "present": bool(permissions),
                "value": permissions,
                "description": "Restricts browser feature usage (camera, microphone, payment) in frames.",
            },
            "samesite_cookie": {
                "present": bool(samesite_found),
                "value": samesite_found,
                "description": (
                    f"SameSite={samesite_found or 'Not Detected'}. "
                    "SameSite=Lax/Strict prevents session cookies from attaching to cross-site iframe requests."
                ),
            },
            "server_information_leakage": {
                "server": server,
                "x_powered_by": x_powered_by,
                "present": bool(server or x_powered_by),
                "description": "Exposes backend software versions which may aid attacker reconnaissance.",
            },
        }

    @classmethod
    def _determine_precedence_note(cls, xfo: Dict[str, Any], csp: Dict[str, Any]) -> str:
        """Determines browser precedence relationship between CSP and XFO."""
        if csp["present"] and csp.get("frame_ancestors_raw") and xfo["present"]:
            return (
                "Standard Precedence Note (RFC 7034 & CSP Level 3): Both CSP 'frame-ancestors' and "
                "'X-Frame-Options' were detected. Modern standards-compliant browsers ignore X-Frame-Options "
                "and enforce CSP frame-ancestors. X-Frame-Options serves as a fallback for legacy browsers."
            )
        elif csp["present"] and csp.get("frame_ancestors_raw"):
            return (
                "Content-Security-Policy 'frame-ancestors' is active and will be enforced by modern browsers. "
                "Consider also providing 'X-Frame-Options: DENY' for legacy browsers (IE11/older clients)."
            )
        elif xfo["present"]:
            return (
                "X-Frame-Options is currently defending this page. It is recommended to migrate to "
                "or add 'Content-Security-Policy: frame-ancestors' to support modern standards and granular origins."
            )
        else:
            return "Neither CSP frame-ancestors nor X-Frame-Options was identified."

    @classmethod
    def _evaluate_overall_posture(
        cls,
        xfo: Dict[str, Any],
        csp: Dict[str, Any],
        secondary: Dict[str, Any],
        http_status: int,
    ) -> Tuple[str, str, str, str]:
        """Synthesizes final assessment status, confidence level, technical explanation, and remediation."""
        has_effective_csp = csp.get("is_effective", False)
        has_effective_xfo = xfo.get("is_effective", False)

        # Case 1: Protected
        if has_effective_csp or has_effective_xfo:
            outcome = "Protected"
            confidence = "High" if (has_effective_csp and has_effective_xfo) else "High"
            
            reasons = []
            if has_effective_csp:
                reasons.append(f"Content-Security-Policy ({csp['status']})")
            if has_effective_xfo:
                reasons.append(f"X-Frame-Options ({xfo['status']})")

            explanation = (
                f"The target application responds with recognized anti-framing protections: {', '.join(reasons)}. "
                "Standard web browsers will enforce these directives and block unauthorized cross-origin framing, "
                "neutralizing UI redressing and clickjacking vectors."
            )

            # Recommendations for continuous improvement
            if not has_effective_csp:
                remediation = (
                    "Your application currently relies solely on X-Frame-Options. Although effective in most browsers, "
                    "modern best practices require adding 'Content-Security-Policy: frame-ancestors \'none\';' (or 'self') "
                    "as specified in W3C CSP Level 3."
                )
            elif not has_effective_xfo:
                remediation = (
                    "Content-Security-Policy frame-ancestors is properly configured. For defense-in-depth and legacy browser "
                    "compatibility, consider also adding 'X-Frame-Options: DENY' as a fallback."
                )
            else:
                remediation = (
                    "Robust multi-layered protection is in place. Ensure that SameSite=Lax or Strict is enforced on all "
                    "session cookies, and regularly audit all authenticated routes in CI/CD tests."
                )

            return outcome, confidence, explanation, remediation

        # Case 2: Potential Risk
        outcome = "Potential Risk"
        confidence = "Medium"

        explanation = (
            "No recognized anti-framing restrictions were identified in the HTTP response headers. "
            "Neither an effective Content-Security-Policy 'frame-ancestors' directive nor an effective X-Frame-Options "
            "header was provided. While this indicates a potential security misconfiguration, this assessment alone "
            "does not guarantee confirmed exploitability. Actual exploitability depends on whether the page contains "
            "sensitive state-changing actions, enforces SameSite cookies, requires explicit user interaction, or is "
            "protected behind authentication barriers."
        )

        remediation = (
            "Implement modern anti-framing security headers immediately:\n"
            "1. Primary Defense: Add 'Content-Security-Policy: frame-ancestors \'none\';' (if framing is never required) "
            "or 'frame-ancestors \'self\';' (to allow same-origin embedding).\n"
            "2. Legacy Fallback: Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN').\n"
            "3. Cookie Hardening: Ensure all sensitive session cookies include the 'SameSite=Lax' or 'SameSite=Strict' attribute."
        )

        return outcome, confidence, explanation, remediation

    @classmethod
    def _handle_inconclusive(
        cls,
        headers: Dict[str, str],
        http_status: Optional[int],
        url: str,
        final_url: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Generates an inconclusive outcome structure when response is abnormal."""
        return {
            "url": url,
            "final_url": final_url,
            "http_status": http_status,
            "outcome": "Inconclusive",
            "confidence": "Low",
            "explanation": (
                f"{reason} Because the HTTP transaction returned an abnormal status code or was unreachable, "
                "anti-framing protections could not be conclusively determined. Pages returning client or server errors "
                "may behave differently under standard production traffic."
            ),
            "remediation": (
                "Ensure that the target application endpoint is healthy and returning HTTP 200 OK before running "
                "security header verification."
            ),
            "xfo_present": False,
            "xfo_raw": headers.get("x-frame-options"),
            "xfo_status": "Inconclusive",
            "xfo_details": "Response not evaluable.",
            "xfo_directive": None,
            "csp_present": False,
            "csp_raw": headers.get("content-security-policy"),
            "csp_frame_ancestors": None,
            "csp_status": "Inconclusive",
            "csp_details": "Response not evaluable.",
            "csp_sources": [],
            "other_headers": {},
            "precedence_note": "Evaluation was inconclusive.",
        }
