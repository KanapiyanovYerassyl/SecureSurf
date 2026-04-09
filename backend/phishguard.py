"""
Python Backend
Ported from background.js (Chrome extension service worker)

Provides:
  - Heuristic URL analysis
  - Google Safe Browsing API check
  - Page text phishing-phrase analysis
  - Full page scan combining all signals
"""

import re
import requests
from urllib.parse import urlparse
from typing import Optional

# ── Config ────────────────────────────────────────────────────────────────────
GOOGLE_API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY"
GSB_ENDPOINT = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

# ── Heuristic URL analysis ────────────────────────────────────────────────────

SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".click", ".loan"}
BRANDS = ["paypal", "apple", "google", "microsoft", "amazon", "facebook", "instagram", "netflix", "bank"]
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy", "is.gd"}
PHISH_KEYWORDS = ["verify", "secure", "update", "login", "signin", "account", "confirm", "banking", "password", "credential"]

def heuristic_check(url: str) -> dict:
    """
    Analyze a single URL for phishing signals.
    Returns: { risk, score, reasons }
    """
    reasons = []
    score = 0

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname.lower() if parsed.hostname else ""
        full_url = url.lower()
        domain_parts = hostname.split(".")
        registered_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else hostname

        # IP address instead of domain
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
            reasons.append("Uses raw IP address instead of domain")
            score += 3

        # Suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                reasons.append(f"Suspicious TLD: {hostname.split('.')[-1]}")
                score += 2
                break

        # Brand impersonation in subdomain
        for brand in BRANDS:
            if brand in hostname and not registered_domain.startswith(brand):
                reasons.append(f'Brand name "{brand}" used in subdomain (possible impersonation)')
                score += 3

        # Excessive subdomains
        if len(domain_parts) > 4:
            reasons.append("Unusually deep subdomain structure")
            score += 1

        # Hyphenated domain
        if "-" in domain_parts[0]:
            reasons.append("Hyphenated domain name (common in phishing)")
            score += 1

        # HTTP (not HTTPS)
        if parsed.scheme == "http":
            reasons.append("Non-secure HTTP connection")
            score += 1

        # Long URL
        if len(url) > 100:
            reasons.append("Unusually long URL")
            score += 1

        # URL shorteners
        if hostname in URL_SHORTENERS:
            reasons.append("URL shortener detected (destination unknown)")
            score += 1

        # Suspicious keywords in path/query
        for kw in PHISH_KEYWORDS:
            if kw in full_url:
                reasons.append(f'Suspicious keyword in URL: "{kw}"')
                score += 1

        # @ symbol in URL
        if "@" in url:
            reasons.append("'@' symbol in URL (can hide real destination)")
            score += 3

        # Double slash in path
        if "//" in (parsed.path or ""):
            reasons.append("Double slash in URL path")
            score += 1

    except Exception:
        reasons.append("Malformed URL")
        score += 2

    risk = "safe" if score == 0 else "low" if score <= 2 else "medium" if score <= 4 else "high"
    return {"risk": risk, "score": score, "reasons": reasons}


# ── Google Safe Browsing API ──────────────────────────────────────────────────

def google_safe_browsing_check(urls: list[str]) -> set:
    """
    Check URLs against Google Safe Browsing API.
    Returns a set of flagged URLs.
    """
    flagged = set()
    if GOOGLE_API_KEY == "YOUR_GOOGLE_SAFE_BROWSING_API_KEY":
        return flagged  # Skip if no real key configured

    body = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }

    try:
        resp = requests.post(GSB_ENDPOINT, json=body, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        for match in data.get("matches", []):
            flagged.add(match["threat"]["url"])
    except Exception as e:
        print(f"GSB API unavailable, using heuristics only: {e}")

    return flagged


# ── Text analysis ─────────────────────────────────────────────────────────────

URGENCY_PHRASES = [
    "your account has been suspended",
    "verify your identity",
    "act immediately",
    "click here to confirm",
    "your password will expire",
    "unusual activity detected",
    "limited time",
    "within 24 hours",
    "failure to respond",
    "update your payment",
    "confirm your details",
    "you have won",
    "congratulations you",
    "dear customer",
    "dear user",
]

def analyze_text(text: str) -> dict:
    """
    Scan page text for phishing phrases and link density.
    Returns: { score, reasons }
    """
    reasons = []
    score = 0
    lower = text.lower()

    for phrase in URGENCY_PHRASES:
        if phrase in lower:
            reasons.append(f'Phishing phrase detected: "{phrase}"')
            score += 1

    # High link density relative to content
    link_count = len(re.findall(r"https?://", text))
    word_count = len(text.split())
    if link_count > 5 and word_count < 200:
        reasons.append("High link density relative to content")
        score += 1

    return {"score": score, "reasons": reasons}


# ── Summary builder ───────────────────────────────────────────────────────────

def build_summary(page_result: dict, all_results: list[dict]) -> dict:
    high_count = sum(1 for r in all_results if r["risk"] == "high")
    med_count = sum(1 for r in all_results if r["risk"] == "medium")

    overall_risk = page_result["risk"]
    if high_count > 0:
        overall_risk = "high"
    elif med_count > 0 and overall_risk == "safe":
        overall_risk = "medium"

    return {
        "overallRisk": overall_risk,
        "highCount": high_count,
        "medCount": med_count,
        "totalLinks": len(all_results) - 1,   # subtract the page itself
        "flaggedLinks": high_count + med_count,
    }


# ── Public scan functions ─────────────────────────────────────────────────────

def scan_urls(urls: list[str]) -> list[dict]:
    """
    Scan a list of URLs. Returns list of { url, risk, score, reasons }.
    """
    if not urls:
        return []

    # 1. Heuristic pass
    heuristic_results = [{"url": u, **heuristic_check(u)} for u in urls]

    # 2. Google Safe Browsing pass
    gsb_flagged = google_safe_browsing_check(urls)

    # 3. Merge
    for h in heuristic_results:
        if h["url"] in gsb_flagged:
            h["reasons"].append("Flagged by Google Safe Browsing")
            h["risk"] = "high"

    return heuristic_results


def scan_page(page_url: str, urls: list[str], page_text: str = "") -> dict:
    """
    Full page scan: URL analysis + text phishing signals.
    Returns: { page, links, summary }
    """
    url_results = scan_urls([page_url] + urls)
    text_signals = analyze_text(page_text or "")

    # Page-level result
    page_result = next((r for r in url_results if r["url"] == page_url), {
        "url": page_url, "risk": "safe", "score": 0, "reasons": []
    })

    # Merge text signals
    page_result["reasons"] = page_result["reasons"] + text_signals["reasons"]
    if text_signals["score"] > 0 and page_result["risk"] == "safe":
        page_result["risk"] = "high" if text_signals["score"] >= 3 else "medium"

    links = [r for r in url_results if r["url"] != page_url]
    summary = build_summary(page_result, url_results)

    return {"page": page_result, "links": links, "summary": summary}
