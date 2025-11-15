// popup.js
document.addEventListener("DOMContentLoaded", async () => {
  const tabAnalysis = document.getElementById('tab-analysis');
  const tabDetails = document.getElementById('tab-details');
  const viewAnalysis = document.getElementById('view-analysis');
  const viewDetails = document.getElementById('view-details');

  let detailsLoaded = false;
  let activeTabInfo = null;

  // Tab switching logic
  tabAnalysis.addEventListener('click', () => {
    tabAnalysis.classList.add('active');
    tabDetails.classList.remove('active');
    viewAnalysis.classList.add('active');
    viewDetails.classList.remove('active');
    // Ensure analysis view is refreshed if needed
    if (activeTabInfo) loadAnalysisView(activeTabInfo);
  });

  tabDetails.addEventListener('click', async () => {
    tabDetails.classList.add('active');
    tabAnalysis.classList.remove('active');
    viewDetails.classList.add('active');
    viewAnalysis.classList.remove('active');
    // Lazy load details view only when clicked
    if (!detailsLoaded && activeTabInfo) {
      detailsLoaded = true;
      loadDetailsView(activeTabInfo);
    }
  });

  // Get active tab info on load
  activeTabInfo = await getActiveTabInfo();
  if (activeTabInfo) {
    loadAnalysisView(activeTabInfo);
  } else {
    // Show a disabled state if no valid tab is active
    document.getElementById("score-text").textContent = '--';
    document.getElementById("status-text").textContent = 'No Page';
    document.getElementById("reasons-list").innerHTML = `<div>Cannot access the current page.</div>`;
  }
});

// --- VIEW 1: RISK ANALYSIS LOGIC ---
async function loadAnalysisView(tabInfo) {
  const scoreTextEl = document.getElementById("score-text");
  const statusTextEl = document.getElementById("status-text");
  const gaugeArcEl = document.getElementById("gauge-arc");
  const reasonsListEl = document.getElementById("reasons-list");
  
  // NOTE: continueBtn and exitBtn logic has been removed here,
  // as they seemed to be performing the list actions.
  // We will now use dedicated Mark Safe/Unsafe buttons.
  
  function updateUI(result) {
    if (!result || typeof result.score !== 'number') {
      scoreTextEl.textContent = '??';
      statusTextEl.textContent = 'Analysis Failed';
      gaugeArcEl.style.borderColor = '#6c757d';
      gaugeArcEl.style.transform = `rotate(0deg)`;
      reasonsListEl.innerHTML = `<div>Could not analyze this page. Reload required.</div>`;
      return;
    }

    const {
      score,
      reasons,
      url,
      domain
    } = result;
    scoreTextEl.textContent = score;

    // Update gauge
    const rotation = Math.min(180, (score / 100) * 180);
    gaugeArcEl.style.transform = `rotate(${rotation}deg)`;

    // Update status text and color
    if (score <= 25) {
      statusTextEl.textContent = 'SAFE';
      statusTextEl.style.color = 'var(--green)';
      gaugeArcEl.style.borderColor = 'var(--green)';
    } else if (score < 85) {
      statusTextEl.textContent = 'SUSPICIOUS';
      statusTextEl.style.color = 'var(--yellow)';
      gaugeArcEl.style.borderColor = 'var(--yellow)';
    } else {
      statusTextEl.textContent = 'DANGEROUS';
      statusTextEl.style.color = 'var(--red)';
      gaugeArcEl.style.borderColor = 'var(--red)';
    }

    // Populate reasons list
    reasonsListEl.innerHTML = '';
    if (reasons && reasons.length > 0) {
      reasons.forEach(reason => {
        const isNegative = reason.includes('(-');
        const icon = isNegative ? ' 🛡️ ' : ' ⚠️ ';
        const color = isNegative ? 'var(--green)' : 'var(--red)';
        const reasonEl = document.createElement('div');
        reasonEl.className = 'reason-item';
        reasonEl.innerHTML = `<div class="reason-icon" style="color: ${color};">${icon}</div><div class="reason-text">${reason.replace(/\(\S+\)/, '').trim()} <span style="color: #888; font-size: 11px;">${reason.match(/\(\S+\)/)?.[0] || ''}</span></div>`;
        reasonsListEl.appendChild(reasonEl);
      });
    } else {
      reasonsListEl.innerHTML = `<div class="reason-item"><div class="reason-icon"> 🟢 </div><div class="reason-text">No specific risks found.</div></div>`;
    }
    
    // 🟩 FIX: Set up the listeners for the separate Mark as Safe/Unsafe buttons
    const valueToSave = domain || url;
    setupListButtons(valueToSave);
  }
  
  if (!tabInfo || !tabInfo.url || !tabInfo.url.startsWith('http')) {
    updateUI(null);
    return;
  }
  
  const result = await getAnalysisResult(tabInfo);
  updateUI(result);
}

// --- VIEW 2: PAGE DETAILS LOGIC ---
async function loadDetailsView(tabInfo) {
  const loadingEl = document.getElementById('details-loading');
  const contentEl = document.getElementById('details-content');
  
  if (!tabInfo || !tabInfo.url || !tabInfo.url.startsWith('http')) {
    loadingEl.textContent = "Cannot analyze browser or local pages.";
    return;
  }

  loadingEl.classList.remove('hidden');
  contentEl.classList.add('hidden');

  // Get data from content script and browser APIs
  const [pageData, cookieData] = await Promise.all([
    getOnPageData(tabInfo.id),
    getCookieData(tabInfo.url)
  ]);

  if (!pageData) {
    loadingEl.textContent = "Failed to get data. Please reload the page and try again.";
    return;
  }

  loadingEl.classList.add('hidden');
  contentEl.classList.remove('hidden');
  
  const createStatus = (status) => `<span class="status-icon ${status}">●</span>`;

  // --- Populate Core Vitals ---
  const fcpEl = document.getElementById('vitals-fcp');
  const clsEl = document.getElementById('vitals-cls');
  const loadTimeEl = document.getElementById('vitals-load-time');

  const fcp = pageData.performance ?.fcp;
  fcpEl.textContent = fcp ? `${fcp.toFixed(0)}ms` : 'N/A';
  if (fcp) {
    if (fcp > 1800) fcpEl.style.color = 'var(--status-warn)';
    else if (fcp > 3000) fcpEl.style.color = 'var(--status-bad)';
    else fcpEl.style.color = 'var(--status-good)';
  }

  const cls = pageData.performance ?.cls;
  clsEl.textContent = cls ? cls.toFixed(3) : 'N/A';
  if (cls) {
    if (cls > 0.1) clsEl.style.color = 'var(--status-warn)';
    else if (cls > 0.25) clsEl.style.color = 'var(--status-bad)';
    else clsEl.style.color = 'var(--status-good)';
  }
  loadTimeEl.textContent = pageData.loadTime ? `${pageData.loadTime}ms` : 'N/A';

  // --- Populate Page Composition ---
  const formatBytes = (bytes) => {
    if (!bytes && bytes !== 0) return "N/A";
    if (bytes === 0) return "0 KB";
    const kb = bytes / 1024;
    return kb > 1000 ? `${(kb / 1024).toFixed(1)} MB` : `${kb.toFixed(0)} KB`;
  };
  document.getElementById('comp-total').textContent = formatBytes(pageData.performance ?.pageWeight ?.total);
  document.getElementById('comp-js').textContent = formatBytes(pageData.performance ?.pageWeight ?.js);
  document.getElementById('comp-img').textContent = formatBytes(pageData.performance ?.pageWeight ?.image);

  // --- Populate Security & Privacy ---
  document.getElementById('priv-https').innerHTML = pageData.isSecure ? `${createStatus('good')} Yes` : `${createStatus('bad')} No`;

  const cookieCount = cookieData.count ?? 0;
  const cookieStatus = cookieCount < 20 ? 'good' : cookieCount < 50 ? 'warn' : 'bad';
  document.getElementById('priv-cookies').innerHTML = `${createStatus(cookieStatus)} ${cookieCount}`;

  const thirdPartyScriptCount = pageData.security ?.thirdPartyScripts ?? 0;
  const scriptStatus = thirdPartyScriptCount < 5 ? 'good' : thirdPartyScriptCount < 15 ? 'warn' : 'bad';
  document.getElementById('priv-3p-scripts').innerHTML = `${createStatus(scriptStatus)} ${thirdPartyScriptCount}`;

  // --- Populate SEO & Accessibility ---
  const titleLength = pageData.seo ?.title ?.length || 0;
  const titleStatus = titleLength > 10 && titleLength < 60 ? 'good' : 'warn';
  document.getElementById('seo-title').innerHTML = `${createStatus(titleStatus)} ${titleLength} chars`;

  // Logic for interactive meta description
  const descItem = document.getElementById('seo-desc-item');
  const descStatusEl = document.getElementById('seo-desc');
  const descFullEl = document.getElementById('seo-desc-full');

  if (pageData.seo ?.description) {
    descStatusEl.innerHTML = `${createStatus('good')} Present`;
    descFullEl.textContent = pageData.seo.description;
    descItem.onclick = () => {
      descFullEl.classList.toggle('hidden');
    };
  } else {
    descStatusEl.innerHTML = `${createStatus('bad')} Missing`;
    descFullEl.classList.add('hidden');
    descItem.onclick = null; // Remove click handler if no description
  }

  const h1Count = pageData.accessibility ?.h1Count ?? 0;
  const h1Status = h1Count === 1 ? 'good' : 'bad';
  document.getElementById('seo-h1').innerHTML = `${createStatus(h1Status)} ${h1Count} found`;

  const altCount = pageData.accessibility ?.missingAlts ?? 0;
  const altStatus = altCount === 0 ? 'good' : altCount < 5 ? 'warn' : 'bad';
  document.getElementById('seo-alt').innerHTML = `${createStatus(altStatus)} ${altCount} missing`;
}

// --- DATA FETCHING HELPERS ---
async function getActiveTabInfo() {
  const [tab] = await chrome.tabs.query({
    active: true,
    currentWindow: true
  });
  return tab || null;
}

async function getAnalysisResult(tabInfo) {
  // 1. Try to get the cached result first
  const cached = await chrome.storage.local.get("lastAnalysis");
  if (cached.lastAnalysis ?.url === tabInfo.url) {
    return cached.lastAnalysis;
  }

  // 2. If cache miss, request a new analysis
  const pageData = await getOnPageData(tabInfo.id);
  const domSignals = pageData ?.domSignals;
  return new Promise(resolve => {
    chrome.runtime.sendMessage({
      action: "analyzeUrl",
      url: tabInfo.url,
      domSignals: domSignals
    }, (result) => {
      if (chrome.runtime.lastError) {
        console.error(chrome.runtime.lastError.message);
        resolve(null);
      } else {
        resolve(result);
      }
    });
  });
}

async function getOnPageData(tabId) {
  // Request page data from the content script
  try {
    const response = await chrome.tabs.sendMessage(tabId, {
      action: "requestPageData"
    });
    return chrome.runtime.lastError ? null : response;
  } catch (error) {
    return null;
  }
}

async function getCookieData(url) {
  // Use the chrome.cookies API
  try {
    const cookies = await chrome.cookies.getAll({
      url
    });
    return {
      count: cookies.length
    };
  } catch (e) {
    return {
      count: 'N/A'
    };
  }
}


// --- 🟩 NEW LIST MANAGEMENT LOGIC 🟩 ---

/**
 * Helper function to display status messages in the popup UI
 */
function displayStatus(message, color = 'black') {
    const msgEl = document.getElementById("msg");
    if (msgEl) {
        msgEl.textContent = message;
        msgEl.style.color = color;
    } else {
        console.log("Status:", message);
    }
}

/**
 * Attaches event listeners for the "Mark as Safe" and "Mark as Unsafe" buttons.
 * @param {string} value - The domain or URL to add to the list.
 */
function setupListButtons(value) {
    // Assuming your HTML uses these IDs for the buttons in the Analysis view
    const safeBtn = document.getElementById('mark-safe-btn'); 
    const unsafeBtn = document.getElementById('mark-unsafe-btn');

    if (safeBtn) {
        safeBtn.onclick = () => {
            sendListAction('addToWhitelist', value, 'SAFE');
        };
    }

    if (unsafeBtn) {
        unsafeBtn.onclick = () => {
            sendListAction('addToBlacklist', value, 'UNSAFE');
        };
    }
}

/**
 * Sends a message to the background script to update the list.
 */
function sendListAction(action, value, type) {
    displayStatus(`Marking ${type}...`, 'orange');
    
    chrome.runtime.sendMessage({ action: action, value: value }, (response) => {
        if (chrome.runtime.lastError) {
            console.error("Error sending message:", chrome.runtime.lastError.message);
            displayStatus(`Failed to mark as ${type}. See console.`, 'var(--red)');
            return;
        }

        if (response && response.ok) {
            displayStatus(`Marked as ${type}! Reload page to see effect.`, 'var(--green)');
            
            // Disable buttons after successful marking
            document.getElementById('mark-safe-btn')?.setAttribute('disabled', 'true');
            document.getElementById('mark-unsafe-btn')?.setAttribute('disabled', 'true');
        } else {
             displayStatus(`Failed to save to list: ${response?.error || 'Unknown error'}`, 'var(--red)');
        }
    });
}