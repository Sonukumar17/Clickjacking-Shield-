#!/usr/bin/env python3
"""Example Usage of Clickjacking Detection Module

Demonstrates programmatic inspection, batch analysis of multiple sites,
and JSON export using the clickjacking_detection package.
"""

from clickjacking_detection import ClickjackDetector, detect_clickjacking


def main():
    print("=" * 65)
    print(" Clickjacking Detection Python API Example")
    print("=" * 65)

    # ── Example 1: Simple single-site detection ──
    target = "https://github.com"
    print(f"\n[+] Analyzing single target: {target}")
    result = detect_clickjacking(target)

    print(f"    Outcome:       {result['outcome']}")
    print(f"    Confidence:    {result['confidence']}")
    print(f"    X-Frame-Opt:   {result['xfo_status']}")
    print(f"    CSP Ancestors: {result['csp_status']}")
    print(f"    Explanation:   {result['explanation']}")

    # ── Example 2: Batch analysis with custom timeout ──
    test_domains = [
        "https://google.com",
        "https://mozilla.org",
        "https://example.com",
    ]

    print(f"\n[+] Running batch analysis on {len(test_domains)} targets:")
    detector = ClickjackDetector(timeout=5)

    for domain in test_domains:
        res = detector.analyze(domain)
        status_symbol = "🟢" if res["outcome"] == "Protected" else "🟡"
        print(f"    {status_symbol} {domain:25} -> {res['outcome']:15} (HTTP {res['http_status']})")

    print("\n[+] Done!")


if __name__ == "__main__":
    main()
