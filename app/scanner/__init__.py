"""Scanner Package

Exposes security assessment components for URL validation, safe HTTP requests,
and clickjacking vulnerability analysis.
"""

from app.scanner.validator import (
    SecurityValidationError,
    validate_and_normalize_url,
    resolve_hostname_safely,
)
from app.scanner.client import SafeHttpClient
from app.scanner.analyzer import SecurityAnalyzer

__all__ = [
    "SecurityValidationError",
    "validate_and_normalize_url",
    "resolve_hostname_safely",
    "SafeHttpClient",
    "SecurityAnalyzer",
]
