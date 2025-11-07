// popup.js
document.addEventListener("DOMContentLoaded", async () => {
  const urlEl = document.getElementById("url");
  const scoreEl = document.getElementById("score");
  const reasonsEl = document.getElementById("reasons");
  const badgeDot = document.getElementById("dot");
  const badgeText = document.getElementById("badge-text");
  const msgEl = document.getElementById("msg");
  const continueBtn = document.getElementById("continueBtn");
  const exitBtn = document.getElementById("exitBtn");

  function setBadge(score, status) {
    if (status === "whitelisted" || (typeof score === "number" && score <= 25)) {
      badgeDot.style.background = "var(--green)";
      badgeText.textContent = "SAFE";
      badgeText.style.color = "var(--green)";
    } else if (status === "known_phish" || (typeof score === "number" && score >= 85)) {
      badgeDot.style.background = "var(--red)";
      badgeText.textContent = "DANGEROUS";
      badgeText.style.color = "var(--red)";
    } else {
      badgeDot.style.background = "var(--yellow)";
      badgeText.textContent = "SUSPICIOUS";
      badgeText.style.color = "var(--yellow)";
    }
  }

  // get active tab URL
  const tabs = await new Promise(resolve => chrome.tabs.query({ active: true, currentWindow: true }, resolve));
  const tab = tabs && tabs[0];
  const pageUrl = tab ? tab.url : "No active tab";
  urlEl.textContent = pageUrl || "No URL available";

  // ask background for analysis
  chrome.runtime.sendMessage({ action: "analyzeUrl", url: pageUrl }, (resp) => {
    if (chrome.runtime.lastError) {
      console.warn("popup analyzeUrl error:", chrome.runtime.lastError.message);
      scoreEl.textContent = "N/A";
      reasonsEl.textContent = "analysis_failed";
      setBadge(0, "unknown");
      return;
    }
    const r = resp || {};
    scoreEl.textContent = (typeof r.score === "number") ? r.score : "N/A";
    reasonsEl.textContent = (Array.isArray(r.reasons) ? r.reasons.join("; ") : (r.reason || ""));
    setBadge(r.score || 0, r.status || "unknown");

    // Continue button -> add to whitelist
    continueBtn.onclick = () => {
      chrome.runtime.sendMessage({ action: "addToWhitelist", value: pageUrl }, res => {
        msgEl.textContent = "Added to whitelist ✅";
        msgEl.style.color = "green";
        scoreEl.textContent = "0";
        reasonsEl.textContent = "User marked as safe";
        setBadge(0, "whitelisted");
      });
    };

    // Exit button -> add to blacklist
    exitBtn.onclick = () => {
      chrome.runtime.sendMessage({ action: "addToBlacklist", value: pageUrl }, res => {
        msgEl.textContent = "Added to blacklist ❌";
        msgEl.style.color = "red";
        scoreEl.textContent = "100";
        reasonsEl.textContent = "User marked as unsafe";
        setBadge(100, "known_phish");
      });
    };
  });
});
