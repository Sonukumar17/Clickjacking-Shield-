# Clickjacking Detection Engine

A standalone, modular Python cybersecurity tool for evaluating web applications against Clickjacking (UI Redressing) vulnerabilities pursuant to **RFC 7034**, **W3C Content Security Policy Level 3**, and **OWASP Clickjacking Defense Cheat Sheet**.

---

## Features

- **Anti-Framing Evaluation**:
  - `Content-Security-Policy: frame-ancestors` (`'none'`, `'self'`, host lists, wildcards `*`, unquoted keywords).
  - `X-Frame-Options` (`DENY`, `SAMEORIGIN`, deprecated `ALLOW-FROM`, duplicate/conflicting headers).
  - Precedence handling: Modern browsers enforce CSP Level 2/3 `frame-ancestors` over `X-Frame-Options`.
- **SSRF Defense**:
  - Validates URLs and blocks loopback, private IPv4 (`10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`), link-local metadata (`169.254.169.254`), and multicast ranges.
- **Standalone Execution**:
  - Runs with standard Python library (`urllib`) or `requests` if installed.
  - Zero external database or web server requirements.

---

## Directory Contents

```
clickjacking_detection/
├── __init__.py          # Package entrypoint (exports ClickjackDetector, detect_clickjacking)
├── detector.py          # Standalone CLI tool & detection engine
├── example_usage.py     # Code examples for developers
└── README.md            # Documentation and usage guide
```

---

## Quick Start (CLI)

### 1. Basic Scan:
```bash
python clickjacking_detection/detector.py https://example.com
```

### 2. Output Raw JSON:
```bash
python clickjacking_detection/detector.py https://example.com --json
```

### 3. Custom Timeout & Private IP Testing (for internal security labs):
```bash
python clickjacking_detection/detector.py http://localhost:5000 --allow-private --timeout 5
```

---

## Programmatic Python Usage

```python
from clickjacking_detection import detect_clickjacking

# Simple scan
result = detect_clickjacking("https://github.com")

print(result["outcome"])       # 'Protected' | 'Potential Risk' | 'Inconclusive'
print(result["confidence"])    # 'High' | 'Medium' | 'Low'
print(result["xfo_status"])    # 'Protected (DENY)' | 'Missing' | etc.
print(result["csp_status"])    # 'Protected (none)' | 'Missing' | etc.
print(result["remediation"])   # Actionable remediation guidance
```

### Advanced Class-Based Usage:

```python
from clickjacking_detection import ClickjackDetector

detector = ClickjackDetector(timeout=10, allow_private_ips=False)
results = detector.analyze("https://target-site.com")

if results["outcome"] == "Potential Risk":
    print("Vulnerability detected!")
    print(results["explanation"])
    print(results["remediation"])
```
