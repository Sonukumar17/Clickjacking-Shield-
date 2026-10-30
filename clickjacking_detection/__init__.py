"""Clickjacking Detection Package

A standalone, defensive cybersecurity library for assessing anti-framing
protections (X-Frame-Options and Content-Security-Policy frame-ancestors)
against UI Redressing and Clickjacking attacks.
"""

from .detector import ClickjackDetector, detect_clickjacking

__all__ = ["ClickjackDetector", "detect_clickjacking"]
__version__ = "1.0.0"
