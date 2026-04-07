#!/usr/bin/env python3
"""
PhishGuard CLI — quick command-line scanner
Usage:
  python cli.py https://paypal-secure-login.tk/verify
  python cli.py https://google.com https://bit.ly/abc123
"""

import sys
import json
from phishguard import scan_page, scan_urls

RISK_COLORS = {
    "safe":   "\033[92m",   # green
    "low":    "\033[94m",   # blue
    "medium": "\033[93m",   # yellow
    "high":   "\033[91m",   # red
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def color(text, risk):
    return f"{RISK_COLORS.get(risk, '')}{text}{RESET}"


def print_result(r):
    badge = color(f"[{r['risk'].upper()}]", r["risk"])
    print(f"  {badge} {r['url']}")
    for reason in r.get("reasons", []):
        print(f"         › {reason}")


def main():
    urls = sys.argv[1:]
    if not urls:
        print("Usage: python cli.py <url> [url2 ...]")
        sys.exit(1)

    if len(urls) == 1:
        
        result = scan_page(urls[0], [], "")
        summary = result["summary"]

        print(f"\n{BOLD}PhishGuard Scan — {urls[0]}{RESET}")
        print(f"{'─'*60}")
        print(f"Overall risk : {color(summary['overallRisk'].upper(), summary['overallRisk'])}")
        print(f"Signals      : {result['page']['reasons'] or ['none']}")
        print()
    else:
        results = scan_urls(urls)
        print(f"\n{BOLD}PhishGuard Batch Scan — {len(urls)} URLs{RESET}")
        print(f"{'─'*60}")
        for r in results:
            print_result(r)
        print()

        high = sum(1 for r in results if r["risk"] == "high")
        med  = sum(1 for r in results if r["risk"] == "medium")
        print(f"Summary: {color(str(high)+' dangerous', 'high')}  {color(str(med)+' suspicious', 'medium')}")
        print()


if __name__ == "__main__":
    main()
