# ClickjackShield: Clickjacking Detection and Prevention Platform

A modern, responsive, enterprise-grade cybersecurity web application engineered for detecting, understanding, analyzing, and mitigating Clickjacking (UI Redressing) vulnerabilities across web applications.

Designed for educational research, defensive security auditing, and authorized penetration testing pursuant to **RFC 7034**, **W3C Content Security Policy Level 3**, and **OWASP Clickjacking Defense Best Practices**.

---

## Table of Contents

1. [Key Features](#key-features)
2. [Technology Stack](#technology-stack)
3. [Architecture & Directory Structure](#architecture--directory-structure)
4. [Defensive Security Controls](#defensive-security-controls)
5. [Installation & Setup](#installation--setup)
6. [Running the Application](#running-the-application)
7. [Running Automated Tests](#running-automated-tests)
8. [Module Walkthrough](#module-walkthrough)
   - [Detection Engine (Scanner)](#1-detection-engine-scanner)
   - [Educational Demonstration Lab](#2-educational-demonstration-lab)
   - [Security Dashboard & Visual Analytics](#3-security-dashboard--visual-analytics)
   - [Reporting & Multi-Format Export](#4-reporting--multi-format-export)
   - [Prevention & Server Hardening Guide](#5-prevention--server-hardening-guide)
9. [Production Deployment Guidance](#production-deployment-guidance)
10. [Ethical Disclosure & Legal Disclaimer](#ethical-disclosure--legal-disclaimer)

---

## Key Features

- **Automated Anti-Framing Header Analysis**:
  - Deep inspection of `Content-Security-Policy: frame-ancestors` (`'none'`, `'self'`, whitelisted hosts, wildcard `*`, and malformed/unquoted keywords).
  - Accurate evaluation of `X-Frame-Options` (`DENY`, `SAMEORIGIN`, deprecated `ALLOW-FROM`, invalid directives, and conflicting multiple headers).
  - W3C CSP vs RFC 7034 precedence mapping (explaining how modern browsers ignore `X-Frame-Options` when `frame-ancestors` is present).
  - Complementary defense-in-depth header analysis: `Strict-Transport-Security` (HSTS), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `SameSite` session cookie flags, and `Server` banner disclosure.
- **SSRF & Anti-Abuse Hardened Scanner**:
  - Restricts scanning strictly to public HTTPS endpoints.
  - Strict DNS pre-resolution blocking loopback (`127.0.0.0/8`, `::1`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local / cloud metadata (`169.254.169.254`), carrier-grade NAT, and internal domains (`.local`, `.lan`, `.internal`).
  - Safe redirect inspector following up to 5 hops, re-validating SSRF boundaries on every `Location` header.
  - Response size limit (512 KB), aggressive socket timeouts (6s), and sliding-window per-IP rate limiting.
- **Controlled Educational Laboratory**:
  - **Page A (Unprotected)**: Local mock target served without anti-framing headers.
  - **Page B (Protected)**: Local mock target protected with `Content-Security-Policy: frame-ancestors 'none';` and `X-Frame-Options: DENY`.
  - **Interactive Attacker Overlay**: Real-time opacity slider (0% to 100%) showing how decoy buttons ("Claim $1,000 Reward") conceal underlying sensitive actions ("Confirm Transfer").
  - Demonstrates browser-enforced frame refusal when Page B is loaded.
  - Zero sensitive actions or external dependencies; strictly safe and isolated.
- **Executive Security Reports**:
  - Formatted web-based audit view.
  - Downloadable native **PDF Security Reports** generated with ReportLab.
  - Downloadable structured **JSON Export**.
- **Interactive Dark Dashboard**:
  - Responsive cybersecurity dark UI (Dark Navy `#090d16`, Cyan `#06b6d4`, Emerald `#10b981`, Amber `#f59e0b`).
  - Dynamic **Chart.js** data visualizations displaying posture distributions and mechanism coverage.
  - Recent scan logs and quick action tools.
- **Full Historical Audit Database**:
  - SQLite backend supporting search by hostname or URL, outcome filtering, multi-parameter sorting, and single/bulk deletion.
- **Rule-Based Cybersecurity Chatbot (ShieldBot)**:
  - Built-in cybersecurity assistant answering questions about clickjacking, HTTP headers, CSP, frame-ancestors, scan results, and remediation.
  - Pure JavaScript keyword-matching algorithm (zero AI API dependencies, zero external cost, ultra-fast response).
  - Available as both a dedicated full-page experience (`/chatbot`) and an omni-present floating widget across the entire application.

---

## Technology Stack

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Backend** | Python 3.10+ / Flask | Application factory, routing, controllers, security middleware |
| **HTTP Engine** | Python Requests | Hardened HTTP fetcher with custom redirects and size limits |
| **Database** | SQLite 3 | WAL-mode persistent relational storage for audit history |
| **PDF Engine** | ReportLab | Native PDF generation with custom cybersecurity typography |
| **Frontend** | HTML5, CSS3, JavaScript | Modern responsive dark theme, radar scan animations |
| **UI Framework**| Bootstrap 5.3.3 | Responsive grid layout, modals, dismissible alerts |
| **Visual Charts**| Chart.js 4.4.1 | Doughnut posture charts and mechanism breakdown bar charts |
| **Cyber Chatbot**| JavaScript Rule Engine | Rule-based cybersecurity question-answering assistant |
| **Icons** | Font Awesome 6 | Cybersecurity and status icons |
| **Testing** | Pytest | 64 automated tests covering validation, SSRF, analysis, and routes |

---

## Architecture & Directory Structure

```text
AWDP/
├── app/
│   ├── __init__.py               # Flask application factory, middleware & error handlers
│   ├── models.py                 # SQLite database schema, CRUD repository & analytics
│   ├── security.py               # CSRF verification, rate limiting, defensive response headers
│   ├── scanner/
│   │   ├── __init__.py           # Scanner package exports
│   │   ├── validator.py          # URL normalization, DNS resolution & SSRF IP blocking
│   │   ├── client.py             # Safe HTTP client, manual redirect loop & size caps
│   │   └── analyzer.py           # RFC 7034 & CSP frame-ancestors parsing & posture scoring
│   ├── routes/
│   │   ├── main.py               # Landing page, dashboard, and about routes
│   │   ├── scan.py               # Scanner form, async execution, and results view
│   │   ├── reports.py            # Formal report view, JSON export, and PDF generation
│   │   ├── history.py            # Audit history search, filtering, and deletion
│   │   ├── lab.py                # Safe educational laboratory and mock targets
│   │   └── prevention.py         # In-depth remediation and server configuration guide
│   ├── services/
│   │   └── pdf_report.py         # ReportLab cybersecurity PDF generator
│   ├── templates/
│   │   ├── base.html             # Base layout, navbar, CSRF meta, footer
│   │   ├── index.html            # Landing home page with feature cards
│   │   ├── dashboard.html        # Security dashboard with Chart.js analytics
│   │   ├── scanner.html          # Interactive URL analysis tool with animated radar
│   │   ├── scan_results.html     # Real-time scan results and header breakdown
│   │   ├── report.html           # Formal printable security audit report
│   │   ├── history.html          # Historical audit table with modal deletion
│   │   ├── lab.html              # Educational lab workspace with opacity slider
│   │   ├── lab_target_unprotected.html # Page A: Mock vulnerable target
│   │   ├── lab_target_protected.html   # Page B: Mock protected target
│   │   ├── prevention.html       # Server config guides (Flask, Nginx, Apache, Node.js)
│   │   ├── about.html            # Project architecture, methodology, RFC standards
│   │   └── errors/               # Custom HTTP 400, 403, 404, 429, 500 error pages
│   └── static/
│       ├── css/
│       │   └── custom.css        # Cyber dark theme styles, animations, glowing badges
│       └── js/
│           ├── main.js           # CSRF fetch helper, clipboard copy, alert dismiss
│           ├── dashboard.js      # Chart.js initialization and data binding
│           ├── scanner.js        # Form validation, animated scan steps, dynamic errors
│           └── lab.js            # Lab opacity slider, decoy alignment, click logger
├── tests/
│   ├── conftest.py               # Temporary test DB fixtures and client helpers
│   ├── test_validator.py         # SSRF blocking, IPv4/IPv6 private ranges, port checks
│   ├── test_analyzer.py          # XFO, CSP frame-ancestors, precedence, misconfigs
│   ├── test_client.py            # Safe HTTP redirects, redirect loops, SSRF on redirects
│   ├── test_database.py          # SQLite repository CRUD, search, filter, stats
│   ├── test_pdf_report.py        # PDF generation validation
│   └── test_routes.py            # Web endpoints, lab responses, and CSRF protection
├── .env.example                  # Environment variable reference
├── config.py                     # Config classes (Development, Testing, Production)
├── requirements.txt              # Python package dependencies
├── run.py                        # Application entrypoint
├── seed_sample_data.py           # Pre-populates realistic assessment records
└── README.md                     # Comprehensive documentation
```

---

## Defensive Security Controls

1. **SSRF Defense & IP Validation**:
   - Hostnames are resolved to IP addresses prior to HTTP connection.
   - Prohibits IPv4 loopback (`127.0.0.0/8`), private addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local / cloud metadata (`169.254.169.254`), carrier-grade NAT (`100.64.0.0/10`), documentation subnets, broadcast, and IPv6 equivalents (`::1`, `fe80::/10`, `fc00::/7`).
   - Prohibits cloud metadata hostnames (`metadata.google.internal`, `instance-data`, `kubernetes`).
   - Disallows embedded credentials (`https://user:pass@host`).
2. **Re-validated Redirects**:
   - Prohibits open auto-redirects. Redirects (`301`, `302`, `303`, `307`, `308`) are followed step-by-step up to a depth of 5.
   - Each redirect target URL is parsed, normalized, and validated through the SSRF engine before making the next connection.
3. **Application Defense-in-Depth**:
   - **CSRF Tokens**: Cryptographic session tokens (`hmac.compare_digest`) enforced on all state-changing endpoints (`POST`, `DELETE`).
   - **HTTP Headers**: All responses include `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, and self-framing boundaries.
   - **Rate Limiting**: Sliding-window limiter restricts scanning to 30 requests/minute per client IP.
   - **Safe Rendering**: All dynamic user inputs, URLs, and server headers are HTML-escaped by Jinja2 to eliminate Cross-Site Scripting (XSS).

---

## Installation & Setup

### Prerequisites

- **Python 3.10, 3.11, or 3.12+**
- **pip** package manager

### 1. Clone or Navigate to the Project

```powershell
cd c:\Users\Abhisek\OneDrive\Documents\AWDP
```

### 2. Configure Environment

Copy the example environment configuration:

```powershell
Copy-Item .env.example .env
```

### 3. Install Dependencies

Install the required packages:

```powershell
pip install -r requirements.txt
```

---

## Running the Application

### 1. (Optional) Seed Sample Assessment Data

Pre-populate the local database with realistic assessment records (GitHub, Google, misconfigured sites):

```powershell
python seed_sample_data.py
```

### 2. Launch the Application

```powershell
python run.py
```

Output:
```text
======================================================================
  CLICKJACKING DETECTION & PREVENTION PLATFORM (ClickjackShield)
======================================================================
 * Server running on: http://127.0.0.1:5000/
 * Environment:       development
 * Database:          c:\...\clickjack_defense.db
 * Defensive mode:    SSRF defense active, HTTPS restricted
======================================================================
```

Open your browser and navigate to: **`http://127.0.0.1:5000/`**

---

## Running Automated Tests

Execute the comprehensive test suite with `pytest`:

```powershell
pytest -v
```

All 64 test cases will execute:

```text
tests/test_analyzer.py ......................... [ 20%]
tests/test_client.py ....                        [ 26%]
tests/test_database.py ....                      [ 32%]
tests/test_pdf_report.py ...                     [ 37%]
tests/test_routes.py .............               [ 56%]
tests/test_validator.py ........................ [100%]
============================== 64 passed in 1.68s ==============================
```

---

## Module Walkthrough

### 1. Detection Engine (Scanner)
- **URL Analysis**: Enter any public HTTPS destination (e.g. `https://github.com`, `https://owasp.org`).
- **Live Feedback**: Step-by-step animated radar scan updates users as DNS is resolved, redirects are inspected, and headers are parsed.
- **Detailed Findings**:
  - `X-Frame-Options`: Checks for `DENY`, `SAMEORIGIN`, `ALLOW-FROM`, invalid directives, or duplicates.
  - `Content-Security-Policy`: Parses directives for `frame-ancestors`, evaluates source restrictions (`'none'`, `'self'`, trusted origins, or dangerous wildcards `*`).
  - **RFC 7034 Precedence Note**: Notes that modern browsers enforce CSP `frame-ancestors` and ignore `X-Frame-Options` when both are present.
  - **Secondary Headers**: Checks for HSTS, MIME sniffing protection, Referrer Policy, Permissions Policy, and SameSite cookie attributes.
- **Posture Classification**:
  - **Protected**: Recognized anti-framing mechanisms are active.
  - **Potential Risk**: Anti-framing mechanisms are absent or wildcarded.
  - **Inconclusive**: Abnormal HTTP status (4xx/5xx) or unreachable.

### 2. Educational Demonstration Lab
- Located at `/lab`.
- **Target A (Unprotected)**: Harmless mock page with no anti-framing headers (`/lab/demo-target-unprotected`).
- **Page B (Protected)**: Harmless mock page with `CSP: frame-ancestors 'none';` and `X-Frame-Options: DENY` (`/lab/demo-target-protected`).
- **Opacity Slider (0% - 100%)**:
  - At 0%, the victim iframe is completely transparent. The user sees a decoy button ("Claim $1,000 Reward Voucher!"). Clicking it demonstrates how the mouse coordinates align directly with the victim's underlying button.
  - At 50%, both layers are visible, visually revealing the redressing alignment trick.
  - When Target B is selected, the browser blocks the iframe from loading, showing how headers render clickjacking physically impossible.
- **Real-Time Event Logger**: Displays timestamped logs of every interaction and simulated click event.

### 3. Security Dashboard & Visual Analytics
- Located at `/dashboard`.
- **Top Metrics**: Total Audits, Recognized Protections, Potential Risks, and Inconclusive Audits.
- **Chart.js Visualizations**: Interactive doughnut chart of posture distribution and bar chart of mechanism breakdown.
- **Recent Scan Table**: Immediate overview with outcome badges, timestamps, and direct export actions.

### 4. Reporting & Multi-Format Export
- Located at `/report/<id>`.
- **Browser Report**: Formatted security report suitable for presentations.
- **PDF Export (`/report/<id>/pdf`)**: Professional cybersecurity audit report with metadata tables, findings breakdown, technical explanations, and actionable remediation.
- **JSON Export (`/report/<id>/json`)**: Machine-readable JSON output for ingestion into SIEM or vulnerability management tools.

### 5. Prevention & Server Hardening Guide
- Located at `/prevention`.
- **Core Directives**:
  - `Content-Security-Policy: frame-ancestors 'none';`
  - `X-Frame-Options: DENY`
- **Architectural Distinction**: In-depth explanation of `frame-ancestors` (who can embed this page) vs `frame-src` (what this page can embed).
- **SameSite Cookies**: Details how `SameSite=Lax` or `SameSite=Strict` defends authenticated states in cross-site iframes.
- **Production Snippets**: Copyable configurations for:
  - Python Flask (`after_request` and Flask-Talisman)
  - Nginx (`add_header ... always;`)
  - Apache (`Header always set ...`)
  - Node.js (Express & Helmet)
  - Django (`django-csp`)
- **Verification Commands**: Instructions for testing with `curl` and CI/CD automated test suites.

---

## Production Deployment Guidance

### 1. Set Environment Variables
In your production environment, set:

```bash
export FLASK_ENV=production
export FLASK_SECRET_KEY="<generate-a-strong-random-secret-key>"
export HOST=0.0.0.0
export PORT=5000
```

### 2. Run with Gunicorn WSGI Server

```bash
gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app('production')"
```

### 3. Nginx Reverse Proxy Configuration

```nginx
server {
    listen 80;
    server_name clickjack.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name clickjack.example.com;

    ssl_certificate /etc/letsencrypt/live/clickjack.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/clickjack.example.com/privkey.pem;

    # Anti-Framing & Defensive Headers for the Platform
    add_header Content-Security-Policy "frame-ancestors 'self';" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## Ethical Disclosure & Legal Disclaimer

> [!IMPORTANT]
> **Authorized Testing Notice**: This application is provided for educational research, defensive security auditing, and authorized security assessments. 
> 
> Testing against targets without explicit, documented authorization from the system owner is prohibited. The developers assume no liability for misuse of this tool. The scanner enforces strict SSRF defenses to prevent access to private networks, loopback addresses, and cloud provider metadata services.
