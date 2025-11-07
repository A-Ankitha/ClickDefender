// content.js — ClickDefender professional floating card (minimal safe fixes)

(async function() {
  const pageUrl = window.location.href;

  // Don't analyze Google search pages (only links)
  const searchEngines = ["www.google.com", "www.bing.com", "search.yahoo.com", "duckduckgo.com"];
  try { if (searchEngines.includes(new URL(pageUrl).hostname)) return; } catch {}

  // Ensure DOM/body exists before we manipulate body-specific elements.
  if (document.readyState === "loading") {
    await new Promise(resolve => document.addEventListener("DOMContentLoaded", resolve));
  }

  // Helper: promise wrapper for chrome.storage.local.get (callback API)
  function storageGet(keys) {
    return new Promise(resolve => {
      try {
        chrome.storage.local.get(keys, (items) => resolve(items || {}));
      } catch (e) {
        console.warn("chrome.storage.local.get failed:", e);
        resolve({});
      }
    });
  }

  // --- Overlay to block page ---
  const overlay = document.createElement("div");
  overlay.id = "cd-overlay";
  Object.assign(overlay.style, {
    position: "fixed", top: "0", left: "0",
    width: "100vw", height: "100vh",
    background: "rgba(0,0,0,0.7)",
    zIndex: "2147483646",
  });
  // Append overlay to documentElement (works even if body is absent)
  document.documentElement.appendChild(overlay);

  // --- Floating card ---
  function createCard() {
    const container = document.createElement("div");
    container.id = "cd-card";
    Object.assign(container.style, {
      position: "fixed",
      top: "12px",
      right: "12px",
      width: "320px",
      padding: "12px",
      background: "#fff",
      borderRadius: "8px",
      boxShadow: "0 8px 24px rgba(0,0,0,0.2)",
      fontFamily: "Arial, sans-serif",
      fontSize: "13px",
      color: "#111",
      zIndex: "2147483647",
      maxWidth: "calc(100vw - 24px)"
    });

    container.innerHTML = `
      <div id="cd-header" style="display:flex;align-items:center;gap:8px;">
        <div style="font-weight:700">ClickDefender</div>
        <div id="cd-badge" style="margin-left:auto;font-weight:700"></div>
      </div>
      <div style="margin-top:8px;"><strong>URL:</strong> <span id="cd-url" style="word-break:break-all"></span></div>
      <div style="margin-top:6px;"><strong>Score:</strong> <span id="cd-score"></span></div>
      <div style="margin-top:6px;"><strong>Reason:</strong></div>
      <div id="cd-reasons" style="margin-top:4px;color:#333"></div>
      <div style="display:flex;gap:8px;margin-top:10px;">
        <button id="cd-continue" style="flex:1;padding:8px;cursor:pointer">✅ Continue</button>
        <button id="cd-exit" style="flex:1;padding:8px;cursor:pointer">❌ Exit</button>
      </div>
      <div id="cd-msg" style="margin-top:8px;font-size:12px"></div>
    `;
    return container;
  }

  function updateBadge(card, score, status) {
    const badge = card.querySelector("#cd-badge");
    if (status === "whitelisted" || (typeof score === "number" && score <= 25)) {
      badge.textContent = "🟢 SAFE";
      badge.style.color = "green";
    } else if (status === "known_phish" || (typeof score === "number" && score >= 85)) {
      badge.textContent = "🔴 DANGEROUS";
      badge.style.color = "red";
    } else {
      badge.textContent = "🟡 SUSPICIOUS";
      badge.style.color = "orange";
    }
  }

  // --- Heuristic scoring (FIXED: HTTPS subtracts 10) ---
  function runHeuristics(url) {
    let score = 30; // base score
    const reasons = [];

    if (!url) { reasons.push("No URL"); return { score, reasons }; }

    const lower = String(url).toLowerCase();
    if (lower.startsWith("https://")) { score -= 10; reasons.push("Uses HTTPS (-10)"); }
    else if (lower.startsWith("http://")) { score += 10; reasons.push("No HTTPS (+10)"); }

    if (url.length > 75) { score += 18; reasons.push("Long URL (>75 chars) (+18)"); }
    if (lower.includes("@")) { score += 30; reasons.push("Contains '@' (+30)"); }

    try {
      const host = new URL(url).hostname;
      const dotCount = (host.match(/\./g) || []).length;
      if (dotCount >= 3) { score += 12; reasons.push("Multiple subdomains (+12)"); }
      if (host.includes("-")) { score += 8; reasons.push("Hyphen in domain (+8)"); }
    } catch { score += 5; reasons.push("Malformed URL (+5)"); }

    score = Math.min(100, Math.max(0, score));
    return { score, reasons };
  }

  // --- Fetch whitelist/blacklist + analyze ---
  async function analyzeUrl(url) {
    // use wrapper
    const store = await storageGet(["whitelist", "blacklist"]);
    const whitelist = Array.isArray(store.whitelist) ? store.whitelist : [];
    const blacklist = Array.isArray(store.blacklist) ? store.blacklist : [];

    // JSON lists (defensive)
    const localWhitelist = Array.isArray(window.whitelistJson) ? window.whitelistJson : [];
    const localBlacklist = Array.isArray(window.blacklistJson) ? window.blacklistJson : [];

    // Check whitelist
    if (whitelist.includes(url) || localWhitelist.some(e => e && e.url === url)) {
      return { url, score: 0, reasons: ["Previously marked SAFE"], status: "whitelisted" };
    }
    // Check blacklist
    if (blacklist.includes(url) || localBlacklist.some(e => e && e.url === url)) {
      const reasons = localBlacklist.filter(e => e && e.url === url).map(e => e.reason || "Listed in local blacklist");
      return { url, score: 100, reasons, status: "known_phish" };
    }

    // Ask background to check Safe Browsing + heuristics (background has full flow)
    const bgResult = await new Promise(resolve => {
      try {
        chrome.runtime.sendMessage({ action: "analyzeUrl", url }, resp => {
          if (chrome.runtime.lastError) {
            console.warn("analyzeUrl sendMessage error:", chrome.runtime.lastError.message);
            resolve(null);
          } else resolve(resp || null);
        });
      } catch (e) {
        console.warn("analyzeUrl sendMessage exception:", e);
        resolve(null);
      }
    });

    if (bgResult && (bgResult.url || typeof bgResult.score !== "undefined")) {
      return {
        url: bgResult.url || url,
        score: typeof bgResult.score === "number" ? bgResult.score : 30,
        reasons: Array.isArray(bgResult.reasons) ? bgResult.reasons : (bgResult.reason ? [bgResult.reason] : []),
        status: bgResult.status || "unknown"
      };
    }

    // Background didn't respond — fallback to local heuristics
    return runHeuristics(url);
  }

  // --- Analyze and build UI ---
  let result;
  try {
    result = await analyzeUrl(pageUrl);
    console.log("ClickDefender: Background analysis used:", result);
  } catch (e) {
    console.error("ClickDefender: analyzeUrl failed:", e);
    result = { url: pageUrl, score: 30, reasons: ["analysis_error"], status: "unknown" };
  }

  // --- Create card ---
  const card = createCard();

  // Append card to body if available; fallback to documentElement
  try {
    if (document.body) document.body.appendChild(card);
    else document.documentElement.appendChild(card);
  } catch (e) {
    console.error("Failed to append card to DOM:", e);
    // ensure overlay is removed so page isn't blocked
    const existOverlay = document.getElementById("cd-overlay");
    if (existOverlay) existOverlay.remove();
    return;
  }

  card.querySelector("#cd-url").textContent = result.url || pageUrl;
  card.querySelector("#cd-score").textContent = (typeof result.score === "number") ? result.score : "N/A";
  card.querySelector("#cd-reasons").textContent = (Array.isArray(result.reasons) ? result.reasons.join("; ") : String(result.reasons || ""));
  updateBadge(card, result.score || 0, result.status);

    // --- Buttons ---
  const msgEl = card.querySelector("#cd-msg");

  // Continue button
  card.querySelector("#cd-continue").addEventListener("click", async () => {
    try {
      await new Promise(resolve => {
        chrome.runtime.sendMessage({ action: "addToWhitelist", value: pageUrl }, () => resolve());
      });
    } catch (e) {
      console.warn("addToWhitelist error:", e);
    }

    msgEl.textContent = "Added to whitelist ✅";
    msgEl.style.color = "green";

    updateBadge(card, 0, "whitelisted");
    card.querySelector("#cd-score").textContent = "0";
    card.querySelector("#cd-reasons").textContent = "User marked as safe";

    // safe remove
    const existOverlay = document.getElementById("cd-overlay");
    if (existOverlay) existOverlay.remove();
    const existCard = document.getElementById("cd-card");
    if (existCard) existCard.remove();
  });

  // Exit button
  card.querySelector("#cd-exit").addEventListener("click", async () => {
    try {
      await new Promise(resolve => {
        chrome.runtime.sendMessage({ action: "addToBlacklist", value: pageUrl }, () => resolve());
      });
    } catch (e) {
      console.warn("addToBlacklist error:", e);
    }

    msgEl.textContent = "Added to blacklist ❌";
    msgEl.style.color = "red";

    updateBadge(card, 100, "known_phish");
    card.querySelector("#cd-score").textContent = "100";
    card.querySelector("#cd-reasons").textContent = "User marked as unsafe";

    const existOverlay = document.getElementById("cd-overlay");
    if (existOverlay) existOverlay.remove();
    const existCard = document.getElementById("cd-card");
    if (existCard) existCard.remove();

    try { window.location.href = "about:blank"; } catch (e) { window.close(); }
  });

})();
