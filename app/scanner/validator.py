"""Target URL Validation and SSRF Defense Module

Performs strict destination verification to defend against Server-Side Request
Forgery (SSRF), DNS rebinding, private network access, and cloud metadata probing.
Only explicitly validated public HTTPS endpoints are permitted for security assessment.
"""

import ipaddress
import re
import socket
from typing import List, Tuple
from urllib.parse import urlparse


class SecurityValidationError(Exception):
    """Raised when target destination fails security or format validation."""
    pass


# Reserved and private network definitions (IPv4 and IPv6)
DISALLOWED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # Private network (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space / CGNAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private network (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast (RFC 7526)
    ipaddress.ip_network("192.168.0.0/16"),     # Private network (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved / Future use (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast (RFC 919)
    # IPv6 definitions
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation
    ipaddress.ip_network("100::/64"),           # Discard-only
    ipaddress.ip_network("2001::/23"),          # IETF Protocol
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique Local (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

DISALLOWED_DOMAINS_SUFFIXES = [
    ".local",
    ".localhost",
    ".internal",
    ".lan",
    ".home",
    ".corp",
    ".arpa",
    ".invalid",
    ".test",
    ".onion",
]

DISALLOWED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "kubernetes.default",
    "kubernetes",
}

HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def is_ip_disallowed(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks whether an IP address belongs to any private, loopback, or reserved range."""
    # Check built-in properties
    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return True

    # Check against comprehensive disallowed networks
    for net in DISALLOWED_NETWORKS:
        try:
            if ip_obj in net:
                return True
        except TypeError:
            # IPv4 vs IPv6 comparison mismatch handled gracefully
            continue
    return False


def validate_and_normalize_url(raw_url: str, allowed_ports: List[int] = None) -> Tuple[str, str, str]:
    """Validates and normalizes target URL, enforcing public HTTPS and SSRF defense.

    Returns:
        Tuple of (normalized_url, hostname, resolved_ip)

    Raises:
        SecurityValidationError: if validation fails.
    """
    if allowed_ports is None:
        allowed_ports = [443]

    if not raw_url or not isinstance(raw_url, str):
        raise SecurityValidationError("URL cannot be empty.")

    raw_url = raw_url.strip()

    # Pre-parse check for scheme
    if "://" not in raw_url:
        # Prepend https:// if missing
        raw_url = "https://" + raw_url

    try:
        parsed = urlparse(raw_url)
    except Exception as e:
        raise SecurityValidationError(f"Invalid URL structure: {e}")

    # Enforce HTTPS scheme
    if parsed.scheme.lower() != "https":
        raise SecurityValidationError(
            f"Security policy requires HTTPS. Received protocol: '{parsed.scheme}'. "
            "Clickjacking analysis of non-HTTPS targets is restricted to prevent plain-text tampering."
        )

    # Disallow user credentials in URL (e.g. https://user:pass@example.com)
    if parsed.username or parsed.password:
        raise SecurityValidationError("User credentials embedded in target URLs are strictly disallowed.")

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise SecurityValidationError("Target URL must specify a valid hostname.")

    # Check disallowed exact hostnames
    if hostname in DISALLOWED_HOSTNAMES:
        raise SecurityValidationError(
            f"Access to '{hostname}' is blocked by SSRF defense policy (internal/metadata hostname)."
        )

    # Check disallowed domain suffixes
    for suffix in DISALLOWED_DOMAINS_SUFFIXES:
        if hostname.endswith(suffix):
            raise SecurityValidationError(
                f"Access to private/local domain ending in '{suffix}' is blocked by SSRF defense policy."
            )

    # Check port
    port = parsed.port or 443
    if port not in allowed_ports:
        raise SecurityValidationError(
            f"Port {port} is not permitted. Scanner is restricted to approved public HTTPS ports: {allowed_ports}."
        )

    # Check if target is a raw IP literal
    resolved_ip = None
    try:
        ip_obj = ipaddress.ip_address(hostname)
        # It's an IP literal
        if is_ip_disallowed(ip_obj):
            raise SecurityValidationError(
                f"Direct IP address '{hostname}' is in a private, loopback, or reserved range (SSRF blocked)."
            )
        resolved_ip = str(ip_obj)
    except ValueError:
        # Not a direct IP address literal; validate hostname format
        if not HOSTNAME_REGEX.match(hostname):
            raise SecurityValidationError(
                f"Target hostname '{hostname}' is invalid. Must be a valid Fully Qualified Domain Name (FQDN)."
            )

    # Perform safe DNS resolution to identify destination IP and defend against DNS rebinding
    if not resolved_ip:
        resolved_ip = resolve_hostname_safely(hostname)

    # Normalize URL: strip fragments, normalize path
    path = parsed.path if parsed.path else "/"
    query = f"?{parsed.query}" if parsed.query else ""
    port_str = f":{port}" if port != 443 else ""
    normalized_url = f"https://{hostname}{port_str}{path}{query}"

    return normalized_url, hostname, resolved_ip


def resolve_hostname_safely(hostname: str) -> str:
    """Resolves DNS for a hostname and validates all returned IP addresses against SSRF policies.

    Returns:
        The validated primary IP string.

    Raises:
        SecurityValidationError: if hostname cannot be resolved or resolves to any private/internal IP.
    """
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SecurityValidationError(f"Unable to resolve DNS for host '{hostname}': {e.strerror or 'DNS Lookup failed'}")
    except Exception as e:
        raise SecurityValidationError(f"DNS resolution failure for host '{hostname}': {e}")

    if not addr_info:
        raise SecurityValidationError(f"DNS resolution returned no IP records for '{hostname}'.")

    validated_ips = []
    for item in addr_info:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if is_ip_disallowed(ip_obj):
                raise SecurityValidationError(
                    f"Destination '{hostname}' resolves to private/prohibited IP {ip_str} (SSRF blocked)."
                )
            validated_ips.append(ip_str)
        except ValueError:
            raise SecurityValidationError(f"Unrecognized IP representation returned for '{hostname}': {ip_str}")

    if not validated_ips:
        raise SecurityValidationError(f"No valid public IP addresses found for '{hostname}'.")

    return validated_ips[0]
