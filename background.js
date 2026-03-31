// background.js

import { SAFE_BROWSING_API_KEY } from './config.js';
import { runExplainableHeuristics } from './heuristics.js';
import { SHORTENERS } from './shared_constants.js';

let whitelistJson = [];
let blacklistJson = [];

// Load global whitelist and blacklists from JSON files on startup
fetch(chrome.runtime.getURL("whitelist.json")).then(r => r.json()).then(data => {
    whitelistJson = data;
});
fetch(chrome.runtime.getURL("blacklist.json")).then(r => r.json()).then(data => {
    blacklistJson = data;
});

// Store Analysis History
async function saveAnalysisToHistory(result) {
    const store = await chrome.storage.local.get("analysisHistory");
    const history = store.analysisHistory || [];

    history.push({
        ...result,
        timestamp: Date.now()
    });

    await chrome.storage.local.set({ analysisHistory: history });
}

/**
 * Extracts the eTLD+1 (domain.com) from a full URL or returns the input if it's already a domain/invalid.
 */
function getDomainFromValue(value) {
    try {
        const urlObj = new URL(value);
        return urlObj.hostname.replace(/^www\./, "");
    } catch (e) {
        return value;
    }
}

/**
 * Attempts to get certificate information for a given tab.
 */
async function getCertificateInfo(tabId) {
    try {
        const results = await chrome.scripting.executeScript({
            target: { tabId },
            func: () => true
        });

        const securityDetails = results[0]?.result?.securityDetails;
        if (securityDetails && securityDetails.validFrom && securityDetails.validTo) {
            const validFrom = new Date(securityDetails.validFrom * 1000);
            const validTo = new Date(securityDetails.validTo * 1000);
            const validityDurationDays =
                (validTo - validFrom) / (1000 * 60 * 60 * 24);

            return {
                issuer: securityDetails.issuer,
                validityDurationDays: Math.round(validityDurationDays)
            };
        }
    } catch (e) {}

    return null;
}

// MAIN MESSAGE LISTENER
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

    if (msg.action === "analyzeUrl" && msg.url) {
        (async () => {
            let tabId = sender.tab ? sender.tab.id : null;

            if (tabId === null) {
                try {
                    const [activeTab] = await chrome.tabs.query({
                        active: true,
                        currentWindow: true
                    });
                    if (activeTab?.id) tabId = activeTab.id;
                } catch (e) {
                    sendResponse({ error: "Cannot determine tab ID for analysis." });
                    return;
                }
            }

            if (tabId) {
                const result = await analyzeUrlForTab(
                    msg.url,
                    tabId,
                    msg.domSignals || null
                );

                
                // Save Result to History
                
                saveAnalysisToHistory(result);

                sendResponse(result);
            } else {
                sendResponse({ error: "Cannot analyze URL without a valid tab." });
            }
        })();
        return true;
    }


    // Whitelist
    if (msg.action === "addToWhitelist") {
        addToList("whitelist", msg.value)
            .then(() => sendResponse({ ok: true }))
            .catch(e => sendResponse({ ok: false, error: e.message }));
        return true;
    }

    // Blacklist
    if (msg.action === "addToBlacklist") {
        markAsUnsafeAndBlock(msg.value)
            .then(() => sendResponse({ ok: true }))
            .catch(e => sendResponse({ ok: false, error: e.message }));
        return true;
    }

    // Request DOM Signals
    if (msg.action === 'requestPageData') {
        (async () => {
            const [tab] = await chrome.tabs.query({
                active: true,
                currentWindow: true
            });

            if (tab?.url?.startsWith('http')) {
                try {
                    const response = await chrome.tabs.sendMessage(tab.id, {
                        action: 'requestPageData'
                    });
                    sendResponse(response);
                } catch (e) {
                    sendResponse(null);
                }
            } else {
                sendResponse(null);
            }
        })();
        return true;
    }
});


// MAIN ANALYSIS PIPELINE
async function analyzeUrlForTab(originalUrl, tabId, domSignals) {
    const [expanded, certInfo] = await Promise.all([
        expandUrl(originalUrl),
        getCertificateInfo(tabId)
    ]);

    const domain = (() => {
        try {
            return new URL(expanded).hostname.replace(/^www\./, "");
        } catch {
            return expanded;
        }
    })();

    // Global whitelist
    if (whitelistJson.some(e =>
        (e.domain_root?.replace(/^www\./, "") === domain) ||
        e.url === expanded
    )) {
        return {
            url: expanded,
            domain,
            status: "whitelisted",
            score: 0,
            reasons: ["Domain in global whitelist"]
        };
    }

    // Global blacklist
    const blMatch = blacklistJson.find(e =>
        (e.domain_root?.replace(/^www\./, "") === domain) ||
        e.url === expanded
    );
    if (blMatch) {
        return {
            url: expanded,
            domain,
            status: "blacklisted",
            score: 100,
            reasons: [blMatch.reason || "In global blacklist"]
        };
    }

    // User lists
    const { whitelist, blacklist } = await getLists();

    if (whitelist.includes(domain)) {
        return {
            url: expanded,
            domain,
            status: "whitelisted",
            score: 0,
            reasons: ["Previously marked SAFE by user"]
        };
    }
    if (blacklist.includes(domain)) {
        return {
            url: expanded,
            domain,
            status: "blacklisted",
            score: 100,
            reasons: ["Previously marked UNSAFE by user"]
        };
    }

    // Safe Browsing
    const sb = await checkSafeBrowsing(expanded);
    if (sb.malicious) {
        return {
            url: expanded,
            domain,
            status: "known_phish",
            score: 100,
            reasons: ["Listed in Google Safe Browsing"],
            sb
        };
    }

    // Local Heuristics
    const heur = runExplainableHeuristics(expanded, domSignals, certInfo);
    return {
        url: expanded,
        domain,
        status: heur.status,
        score: heur.score,
        reasons: heur.reasons
    };
}



// UTILITY FUNCTIONS 

async function getLists() {
    const store = await chrome.storage.local.get(["whitelist", "blacklist"]);
    return {
        whitelist: store.whitelist || [],
        blacklist: store.blacklist || []
    };
}

async function addToList(listName, value) {
    const valueToStore = getDomainFromValue(value);
    const store = await chrome.storage.local.get([listName]);
    const arr = store[listName] || [];

    if (!arr.includes(valueToStore)) {
        arr.push(valueToStore);
        await chrome.storage.local.set({ [listName]: arr });
    }
}

async function expandUrl(url) {
    try {
        const domain = new URL(url).hostname;
        if (!SHORTENERS.includes(domain)) return url;

        const resp = await fetch(url, { method: "HEAD", redirect: "manual" });
        if (resp.status >= 300 && resp.status < 400 && resp.headers.get("Location")) {
            const loc = resp.headers.get("Location");
            return loc.startsWith("http") ? loc : new URL(loc, url).href;
        }
    } catch {}
    return url;
}

async function checkSafeBrowsing(url) {
    if (!SAFE_BROWSING_API_KEY) {
        console.warn("SAFE_BROWSING_API_KEY is not set.");
        return { malicious: false, info: null };
    }

    try {
        const apiUrl =
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`;

        const resp = await fetch(apiUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                client: {
                    clientId: "ClickDefender",
                    clientVersion: "1.0"
                },
                threatInfo: {
                    threatTypes: [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url }]
                }
            })
        });

        if (!resp.ok) {
            return { malicious: false, info: null };
        }

        const data = await resp.json();
        if (data?.matches?.length) {
            return { malicious: true, info: data.matches };
        }
    } catch {}

    return { malicious: false, info: null };
}



// BLOCKING MECHANISM 

async function markAsUnsafeAndBlock(value) {
    const domain = getDomainFromValue(value);

    const store = await chrome.storage.local.get(["whitelist", "blacklist"]);
    let whitelist = store.whitelist || [];
    let blacklist = store.blacklist || [];

    whitelist = whitelist.filter(item => item !== domain);
    if (!blacklist.includes(domain)) blacklist.push(domain);

    await chrome.storage.local.set({ whitelist, blacklist });

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab) {
        chrome.tabs.update(tab.id, { url: chrome.runtime.getURL("blocked.html") });
    }
}
