// popup.js 
document.addEventListener("DOMContentLoaded", () => {
  const urlText = document.getElementById("urlText");
  const statusText = document.getElementById("statusText");
  const scoreNum = document.getElementById("scoreNum");
  const reason = document.getElementById("reason");
  const continueBtn = document.getElementById("continueBtn");
  const exitBtn = document.getElementById("exitBtn");
  const msgEl = document.getElementById("msg");

  // Get last clicked URL
  chrome.runtime.sendMessage({ action: "getLastClickedUrl" }, (res) => {
    const url = res?.url || null;
    urlText.textContent = url || "No link clicked yet";

    if (!url) {
      statusText.textContent = "—";
      scoreNum.textContent = "—";
      reason.textContent = "No URL available.";
      return;
    }

    // Analyze via background (Safe Browsing mandatory)
    chrome.runtime.sendMessage({ action: "analyzeUrl", url }, (result) => {
      if (!result) return;
      scoreNum.textContent = result.score ?? "—";
      reason.textContent = (result.reasons && result.reasons.length) ? result.reasons.join("; ") : result.status || "No reason";

      if (result.status === "whitelisted" || (result.score !== undefined && result.score <= 25)) statusText.textContent = "🟢 SAFE";
      else if (result.status === "known_phish" || (result.score !== undefined && result.score >= 85)) statusText.textContent = "🔴 DANGEROUS";
      else statusText.textContent = "🟡 SUSPICIOUS";
    });
  });

  continueBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "getLastClickedUrl" }, (res) => {
      const url = res?.url;
      if (!url) return;
      chrome.runtime.sendMessage({ action: "addToWhitelist", value: url }, () => {
        msgEl.textContent = "✅ Marked SAFE";
        msgEl.style.color = "green";
      });
    });
  });

  exitBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({ action: "getLastClickedUrl" }, (res) => {
      const url = res?.url;
      if (!url) return;
      chrome.runtime.sendMessage({ action: "addToBlacklist", value: url }, () => {
        msgEl.textContent = "❌ Marked UNSAFE";
        msgEl.style.color = "red";
      });
    });
  });
});
