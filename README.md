# SecureSurf – Chrome Extension(BETA)

<br />
<div align="center">
  <a href="https://github.com/othneildrew/Best-README-Template">
    <img src="./logo.png" alt="Logo" width="200" height="200">
  </a>
</div>

Real-time phishing detection for emails and web browsing.

---

##  Project Structure

```
SecureSurf/
├── manifest.json          # Extension config (Manifest v3)
├── popup.html (WIP)           # Extension popup UI
├── icons/                 # Extension icons 
│   ├── icon16.png
│   ├── icon48.png
│   └── icon128.png
└── src/
        (WIP)
 
```

---

## How to Load in Chrome (Development)

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer Mode** (top-right toggle)
3. Click **"Load unpacked"**
4. Select the `phishguard/` folder
5. The extension icon should appear in your toolbar

---

##  API Key Setup (Optional but recommended)

The extension works **without an API key** using heuristics only.

To enable **Google Safe Browsing** (more accurate):

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Enable the **Safe Browsing API**
3. Create an API key
4. In `src/background.js`, replace:
   ```js
   const GOOGLE_API_KEY = "YOUR_GOOGLE_SAFE_BROWSING_API_KEY";
   ```
   with your actual key.

---

##  How It Works

### Heuristic Detection
Analyzes URLs for:
- Raw IP addresses instead of domains
- Suspicious TLDs (`.xyz`, `.tk`, `.ml`, etc.)
- Brand impersonation in subdomains (e.g. `paypal.evil.com`)
- Excessive subdomain depth
- Hyphenated domains
- HTTP (non-HTTPS) connections
- URL shorteners
- Suspicious keywords (`verify`, `login`, `confirm`, etc.)
- `@` symbol in URLs
- Phishing phrases in page text (`"verify your identity"`, etc.)

### Google Safe Browsing API
Cross-checks URLs against Google's database of known phishing/malware URLs.

---

##  Risk Levels

| Level | Meaning |
|-------|---------|
| 🟢 SAFE | No signals detected |
| 🔵 LOW | Minor signals, probably fine |
| 🟡 CAUTION | Suspicious content, be careful |
| 🔴 DANGER | High confidence phishing attempt |

---






## Testing Phishing Detection

Use safe test resources:
- **PhishTank** (phishtank.com) – database of known phishing URLs
- **Google Safe Browsing Test** – `testsafebrowsing.appspot.com`
- Try URLs like: `http://paypal-secure-login.tk/verify`

---



## References

- [Chrome Extension Docs](https://developer.chrome.com/docs/extensions/)
- [Google Safe Browsing API](https://developers.google.com/safe-browsing)
- [Manifest V3 Migration](https://developer.chrome.com/docs/extensions/migrating/)
