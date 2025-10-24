// content.js — ClickDefender professional floating card

(async function() {
  const pageUrl = window.location.href;

  // Don't analyze Google search pages (only links)
  const searchEngines = ["www.google.com", "www.bing.com", "search.yahoo.com", "duckduckgo.com"];
  try { if (searchEngines.includes(new URL(pageUrl).hostname)) return; } catch {}

  // --- Overlay to block page ---
  const overlay = document.createElement("div");
  overlay.id = "cd-overlay";
  Object.assign(overlay.style, {
    position: "fixed", top: "0", left: "0",
    width: "100vw", height: "100vh",
    background: "rgba(0,0,0,0.7)",
    zIndex: "2147483646",
  });
  document.documentElement.appendChild(overlay);

  // --- Floating card ---
  function createCard() {
    const container = document.createElement("div");
    container.id = "cd-card";
    Object.assign(container.style, {
      position: "fixed",
      top: "12px",
      right: "12px",
      width: "300px",
      padding: "12px",
      background: "#fff",
      borderRadius: "8px",
      boxShadow: "0 8px 24px rgba(0,0,0,0.2)",
      fontFamily: "Arial, sans-serif",
      fontSize: "13px",
      color: "#111",
      zIndex: "2147483647",
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
    if(status==="whitelisted" || score<=25){
      badge.textContent = "🟢 SAFE";
      badge.style.color = "green";
    } else if(status==="known_phish" || score>=85){
      badge.textContent = "🔴 DANGEROUS";
      badge.style.color = "red";
    } else {
      badge.textContent = "🟡 SUSPICIOUS";
      badge.style.color = "orange";
    }
  }

  // --- Heuristic scoring ---
  function runHeuristics(url){
    let score = 30; // base score
    const reasons = [];

    if(!url) { reasons.push("No URL"); return {score, reasons}; }

    const lower = url.toLowerCase();
    if(lower.startsWith("https://")) reasons.push("Uses HTTPS");
    else if(lower.startsWith("http://")) { score+=10; reasons.push("No HTTPS"); }

    if(url.length>75){ score+=18; reasons.push("Long URL (>75 chars)"); }
    if(lower.includes("@")){ score+=30; reasons.push("Contains '@'"); }

    try{
      const host = new URL(url).hostname;
      const dotCount = (host.match(/\./g)||[]).length;
      if(dotCount>=3){ score+=12; reasons.push("Multiple subdomains"); }
      if(host.includes("-")){ score+=8; reasons.push("Hyphen in domain"); }
    } catch{ score+=5; reasons.push("Malformed URL"); }

    return {score:Math.min(100,score), reasons};
  }

  // --- Fetch whitelist/blacklist + analyze ---
  async function analyzeUrl(url){
    const { whitelist=[], blacklist=[] } = await chrome.storage.local.get(["whitelist","blacklist"]);

    // JSON lists (replace with your actual JSON import if needed)
    const localWhitelist = window.whitelistJson || [];
    const localBlacklist = window.blacklistJson || [];

    // Check whitelist
    if(whitelist.includes(url) || localWhitelist.some(e=>e.url===url)){
      return {url, score:0, reasons:["Previously marked SAFE"], status:"whitelisted"};
    }
    // Check blacklist
    if(blacklist.includes(url) || localBlacklist.some(e=>e.url===url)){
      return {url, score:100, reasons: localBlacklist.filter(e=>e.url===url).map(e=>e.reason), status:"known_phish"};
    }

    // Safe Browsing mandatory
    const sb = await new Promise(resolve=>{
      chrome.runtime.sendMessage({action:"checkSafeBrowsing", url}, resolve);
    });
    if(sb?.malicious) return {url, score:100, reasons:["Listed in Safe Browsing"], status:"known_phish"};

    // Heuristics fallback
    return runHeuristics(url);
  }

  const result = await analyzeUrl(pageUrl);

  // --- Create card ---
  const card = createCard();
  document.body.appendChild(card);

  card.querySelector("#cd-url").textContent = result.url;
  card.querySelector("#cd-score").textContent = result.score;
  card.querySelector("#cd-reasons").textContent = result.reasons.join("; ");
  updateBadge(card,result.score,result.status);

  // --- Buttons ---
  const msgEl = card.querySelector("#cd-msg");
  
  // Continue button: add to whitelist, remove overlay/card to continue browsing
  card.querySelector("#cd-continue").addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ action: "addToWhitelist", value: pageUrl });
    msgEl.textContent = "Added to whitelist ✅";
    msgEl.style.color = "green";
    updateBadge(card, 0, "whitelisted");
    card.querySelector("#cd-score").textContent = "0";
    card.querySelector("#cd-reasons").textContent = "User marked as safe";
    overlay.remove();
    card.remove();  // remove card so user can browse page normally
  });

  // Exit button: add to blacklist, remove overlay/card, then redirect to safe page
  card.querySelector("#cd-exit").addEventListener("click", async () => {
    await chrome.runtime.sendMessage({ action: "addToBlacklist", value: pageUrl });
    msgEl.textContent = "Added to blacklist ❌";
    msgEl.style.color = "red";
    updateBadge(card, 100, "known_phish");
    card.querySelector("#cd-score").textContent = "100";
    card.querySelector("#cd-reasons").textContent = "User marked as unsafe";
    overlay.remove();
    card.remove();
    window.location.href = "about:blank";  // redirect to safe page
  });
})();
