const scanBtn = document.getElementById("scanBtn");
const loadingState = document.getElementById("loadingState");
const idleState = document.getElementById("idleState");
const resultsSection = document.getElementById("results-section");
const scanLine = document.getElementById("scanLine");
const currentUrlEl = document.getElementById("currentUrl");

async function init() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    currentUrlEl.textContent = tab.url;

    const cacheKey = `scan_${tab.url}`;
    chrome.storage.local.get(cacheKey, (data) => {
        const cached = data[cacheKey];
        if (cached && Date.now() - cached.timestamp < 60000) {
            showResults(cached);
        }
    });
}

scanBtn.addEventListener("click", async() => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    setScanning(true);

    try {
        const pageData = await new Promise((resolve, reject) => {
            chrome.tabs.sendMessage(tab.id, { type: "REQUEST_SCAN" }, (response) => {
                if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
                else resolve(response);
            });
        });

        const result = await new Promise((resolve, reject) => {
            chrome.runtime.sendMessage({
                    type: "SCAN_PAGE",
                    url: pageData.currentUrl,
                    urls: pageData.urls,
                    pageText: pageData.pageText
                },
                (response) => {
                    if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
                    else resolve(response);
                }
            );
        });

        showResults(result);
    } catch (err) {
        console.error("Scan error:", err);
        showError();
    } finally {
        setScanning(false);
    }
});

function setScanning(active) {
    scanBtn.disabled = active;
    scanBtn.textContent = active ? "Scanning..." : "Scan Page";
    scanLine.style.display = active ? "block" : "none";
    document.body.classList.toggle("scanning", active);

    if (active) {
        idleState.classList.remove("visible");
        loadingState.classList.add("visible");
        resultsSection.classList.remove("visible");
    }
}

function showResults(result) {
    loadingState.classList.remove("visible");
    idleState.classList.remove("visible");
    resultsSection.classList.add("visible");

    const summary = result.summary;
    const links = result.links || [];

    document.getElementById("totalLinks").textContent = summary.totalLinks;
    document.getElementById("medCount").textContent = summary.medCount;
    document.getElementById("highCount").textContent = summary.highCount;

    const riskLevel = document.getElementById("riskLevel");
    const riskSub = document.getElementById("riskSub");

    const riskConfig = {
        safe: { color: "var(--safe)", label: "SAFE", sub: "No threats detected" },
        low: { color: "var(--low)", label: "LOW RISK", sub: "Minor signals detected" },
        medium: { color: "var(--medium)", label: "CAUTION", sub: "Suspicious content found" },
        high: { color: "var(--high)", label: "DANGER", sub: "Phishing threat detected!" }
    };

    const cfg = riskConfig[summary.overallRisk] || riskConfig.safe;
    riskLevel.textContent = cfg.label;
    riskLevel.style.color = cfg.color;
    riskSub.textContent = cfg.sub;

    animateGauge(summary.overallRisk, cfg.color);

    const urlList = document.getElementById("urlList");
    const flagged = links.filter(l => l.risk !== "safe");

    if (flagged.length === 0) {
        urlList.innerHTML = `
      <div style="text-align:center; padding: 16px; color: var(--muted); font-size: 12px;">
        ✓ No suspicious links detected
      </div>`;
    } else {
        urlList.innerHTML = "";
        const order = { high: 0, medium: 1, low: 2, safe: 3 };
        flagged.sort((a, b) => order[a.risk] - order[b.risk]);

        flagged.slice(0, 20).forEach(item => {
            const el = createUrlItem(item);
            urlList.appendChild(el);
        });
    }
}

function createUrlItem(item) {
    const div = document.createElement("div");
    div.className = `url-item ${item.risk}`;

    let hostname = item.url;
    try { hostname = new URL(item.url).hostname; } catch {}

    div.innerHTML = `
    <div class="url-top">
      <span class="risk-badge ${item.risk}">${item.risk}</span>
      <span class="url-text" title="${item.url}">${hostname}</span>
    </div>
    <div class="url-reasons">
      ${item.reasons.slice(0, 4).map(r => `<div class="reason-item">${r}</div>`).join("")}
    </div>
  `;

  div.addEventListener("click", () => div.classList.toggle("expanded"));
  return div;
}

function animateGauge(risk, color) {
  const arc = document.getElementById("gaugeArc");
  const needle = document.getElementById("gaugeNeedle");

  const riskAngles = { safe: 0, low: 0.25, medium: 0.55, high: 0.9 };
  const pct = riskAngles[risk] || 0;

  const offset = 188.5 - (188.5 * pct);
  arc.style.strokeDashoffset = offset;
  arc.style.stroke = color;

  const angle = -90 + (pct * 180);
  needle.style.transform = `rotate(${angle}deg)`;
}

function showError() {
  idleState.classList.add("visible");
  loadingState.classList.remove("visible");
  document.getElementById("riskSub") && (document.getElementById("riskSub").textContent = "Scan failed. Try reloading the page.");
}

init();