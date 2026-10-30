"""Safe HTTP Client for Security Assessment

Provides a hardened HTTP fetcher that manually traces and validates redirects,
enforces payload size limits, avoids credential leakage, and respects timeouts.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
import requests

from app.scanner.validator import SecurityValidationError, validate_and_normalize_url


class SafeHttpClient:
    """HTTP client hardened against SSRF, infinite redirects, and payload flooding."""

    def __init__(
        self,
        timeout: int = 6,
        max_redirects: int = 5,
        max_response_size: int = 524288,  # 512 KB
        user_agent: Optional[str] = None,
        allowed_ports: Optional[List[int]] = None,
    ):
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_response_size = max_response_size
        self.user_agent = user_agent or "ClickjackShield-Audit-Scanner/1.0 (Defensive Security Audit)"
        self.allowed_ports = allowed_ports or [443]

    def fetch(self, initial_url: str) -> Dict[str, Any]:
        """Performs a safe HTTP request to retrieve headers and inspect redirect chain.

        Returns:
            Dict containing:
                - status_code: int
                - url: initial URL
                - final_url: final destination URL
                - hostname: target hostname
                - ip_address: resolved target IP
                - headers: Dict of response headers (lowercased keys)
                - redirects: List of redirect hops
                - content_length: estimated bytes read
        """
        # Step 1: Validate initial URL & SSRF checks
        current_url, hostname, resolved_ip = validate_and_normalize_url(
            initial_url, allowed_ports=self.allowed_ports
        )

        redirects: List[Dict[str, Any]] = []
        hop_count = 0
        final_response_headers: Dict[str, str] = {}
        final_status_code = None

        session = requests.Session()
        # Ensure session does not use environment proxies or keep unauthorized cookies
        session.trust_env = False

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }

        while True:
            try:
                resp = session.get(
                    current_url,
                    headers=headers,
                    timeout=(self.timeout, self.timeout),
                    allow_redirects=False,
                    stream=True,
                    verify=True,
                )
            except requests.exceptions.SSLError as e:
                raise SecurityValidationError(f"SSL/TLS Handshake failed for {current_url}: {e}")
            except requests.exceptions.Timeout:
                raise SecurityValidationError(f"Connection timed out ({self.timeout}s) while contacting {current_url}")
            except requests.exceptions.ConnectionError as e:
                raise SecurityValidationError(f"Could not connect to {current_url}: {e}")
            except Exception as e:
                raise SecurityValidationError(f"Network error querying {current_url}: {e}")

            # Read up to max_response_size to prevent memory exhaustion
            bytes_read = 0
            for chunk in resp.iter_content(chunk_size=4096):
                bytes_read += len(chunk)
                if bytes_read > self.max_response_size:
                    break
            resp.close()

            # Normalize headers to lowercase keys for consistent analysis
            header_dict = {k.lower(): v for k, v in resp.headers.items()}
            final_response_headers = header_dict
            final_status_code = resp.status_code

            # Check for redirect status codes (301, 302, 303, 307, 308)
            if resp.status_code in (301, 302, 303, 307, 308) and "location" in header_dict:
                hop_count += 1
                if hop_count > self.max_redirects:
                    raise SecurityValidationError(
                        f"Exceeded maximum allowed redirects ({self.max_redirects}). Possible redirect loop."
                    )

                next_location = header_dict["location"].strip()
                # Resolve relative redirect URLs against the current URL
                next_url = urljoin(current_url, next_location)

                redirects.append({
                    "hop": hop_count,
                    "from": current_url,
                    "to": next_url,
                    "status_code": resp.status_code,
                })

                # CRITICAL DEFENSE: Validate the redirect destination URL against SSRF and allowed scheme
                current_url, hostname, resolved_ip = validate_and_normalize_url(
                    next_url, allowed_ports=self.allowed_ports
                )
                continue

            # Not a redirect or final hop reached
            break

        return {
            "status_code": final_status_code,
            "url": initial_url,
            "final_url": current_url,
            "hostname": hostname,
            "ip_address": resolved_ip,
            "headers": final_response_headers,
            "redirects": redirects,
        }
