"""
PhishGuard - Flask API Server

Endpoints:
  POST /scan/urls     — scan a list of URLs
  POST /scan/page     — full page scan (URL + links + text)
  GET  /scan/url      — quick single-URL check via query param ?url=...
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
from phishguard import scan_urls, scan_page, heuristic_check

app = Flask(__name__)
CORS(app)   # allow cross-origin requests (e.g. from a browser extension or frontend)


# ── Health check ──────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return jsonify({"status": "ok", "service": "PhishGuard API"})


# ── Single URL (quick check) ──────────────────────────────────────────────────

@app.route("/scan/url", methods=["GET"])
def scan_single_url():
    """
    GET /scan/url?url=https://example.com
    Quick heuristic check on one URL (no GSB, no text analysis).
    """
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "Missing 'url' query parameter"}), 400

    result = heuristic_check(url)
    result["url"] = url
    return jsonify(result)


# ── Batch URL scan ────────────────────────────────────────────────────────────

@app.route("/scan/urls", methods=["POST"])
def scan_urls_endpoint():
    """
    POST /scan/urls
    Body: { "urls": ["https://...", ...] }
    Returns: list of { url, risk, score, reasons }
    """
    data = request.get_json(force=True, silent=True) or {}
    urls = data.get("urls", [])

    if not isinstance(urls, list) or not urls:
        return jsonify({"error": "'urls' must be a non-empty list"}), 400

    urls = [str(u) for u in urls[:100]]  # cap at 100 to mirror content.js limit
    results = scan_urls(urls)
    return jsonify(results)


# ── Full page scan ────────────────────────────────────────────────────────────

@app.route("/scan/page", methods=["POST"])
def scan_page_endpoint():
    """
    POST /scan/page
    Body: {
        "url":       "https://current-page.com",
        "urls":      ["https://link1.com", ...],   # optional
        "page_text": "visible text on the page"    # optional
    }
    Returns: { page, links, summary }
    """
    data = request.get_json(force=True, silent=True) or {}
    page_url = data.get("url", "").strip()

    if not page_url:
        return jsonify({"error": "Missing 'url' field"}), 400

    urls = [str(u) for u in data.get("urls", [])[:50]]   # cap mirrors content.js
    page_text = str(data.get("page_text", ""))[:5000]     # cap mirrors content.js

    result = scan_page(page_url, urls, page_text)
    return jsonify(result)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("PhishGuard API running on http://localhost:5000")
    app.run(debug=True, port=5000)
