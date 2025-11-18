// background.js
import {
    SAFE_BROWSING_API_KEY
} from './config.js';
import {
    runExplainableHeuristics
} from './heuristics.js';
import {
    SHORTENERS
} from './shared_constants.js';

let whitelistJson = [];
let blacklistJson = [];

// Load global whitelist and blacklists from JSON files on startup
fetch(chrome.runtime.getURL("whitelist.json")).then(r => r.json()).then(data => {
    whitelistJson = data;
});
fetch(chrome.runtime.getURL("blacklist.json")).then(r => r.json()).then(data => {
    blacklistJson = data;
});

/**
 * Extracts the eTLD+1 (domain.com) from a full URL or returns the input if it's already a domain/invalid.
 * @param {string} value - The URL or domain string.
 * @returns {string} The extracted domain (e.g., 'example.com') or the original value if it's not a recognizable URL.
 */
function getDomainFromValue(value) {
    try {
        // Attempt to create a URL object. If successful, extract and normalize the hostname.
        const urlObj = new URL(value);
        return urlObj.hostname.replace(/^www\./, "");
    } catch (e) {
        // If it fails (it's likely already a domain or an invalid input), return the original value.
        return value;
    }
}

/**
 * Attempts to get certificate information for a given tab.
 * Note: This functionality is often restricted in modern browsers and may not return details.
 */
async function getCertificateInfo(tabId) {
    try {
        const results = await chrome.scripting.executeScript({
            target: {
                tabId: tabId
            },
            func: () => {
                // This function is executed in the content script context.
                // In modern Chrome, securityDetails are restricted.
                return true;
            }
        });
        const securityDetails = results[0] ?.result ?.securityDetails;
        if (securityDetails && securityDetails.validFrom && securityDetails.validTo) {
            const validFrom = new Date(securityDetails.validFrom * 1000);
            const validTo = new Date(securityDetails.validTo * 1000);
            const validityDurationDays = (validTo - validFrom) / (1000 * 60 * 60 * 24);
            return {
                issuer: securityDetails.issuer,
                validityDurationDays: Math.round(validityDurationDays)
            };
        }
    } catch (e) {
        // console.warn("Could not get certificate info:", e.message);
    }
    return null;
}

// Main listener for messages from content scripts and the popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.action === "analyzeUrl" && msg.url) {
        (async () => {
            let tabId = sender.tab ? sender.tab.id : null;

            // If the message is not coming from a tab (e.g., from the popup),
            // we must find the currently active tab ID.
            if (tabId === null) {
                try {
                    const [activeTab] = await chrome.tabs.query({
                        active: true,
                        currentWindow: true
                    });
                    if (activeTab && activeTab.id) {
                        tabId = activeTab.id;
                    }
                } catch (e) {
                    console.error("Failed to get active tab ID:", e);
                    sendResponse({
                        error: "Cannot determine tab ID for analysis."
                    });
                    return;
                }
            }

            // We must have a valid tabId to continue with analysis
            if (tabId) {
                analyzeUrlForTab(msg.url, tabId, msg.domSignals || null).then(sendResponse);
            } else {
                sendResponse({
                    error: "Cannot analyze URL without a valid tab context."
                });
            }
        })();
        return true; // Indicates asynchronous response
    }

    // Handlers for Whitelist/Blacklist functionality
    if (msg.action === "addToWhitelist") {
        addToList("whitelist", msg.value).then(() => sendResponse({
            ok: true
        })).catch(e => sendResponse({ ok: false, error: e.message }));
        return true;
    }
    if (msg.action === "addToBlacklist") {
        markAsUnsafeAndBlock(msg.value)
            .then(() => sendResponse({ ok: true }))
            .catch(e => sendResponse({ ok: false, error: e.message }));
        return true;
    }


    if (msg.action === 'requestPageData') {
        (async () => {
            const [tab] = await chrome.tabs.query({
                active: true,
                currentWindow: true
            });
            if (tab && tab.url && tab.url.startsWith('http')) {
                try {
                    // Forward the request to the content script of the active tab
                    const response = await chrome.tabs.sendMessage(tab.id, {
                        action: 'requestPageData'
                    });
                    sendResponse(response);
                } catch (e) {
                    // This can fail if the content script isn't injected yet (e.g., on a new tab)
                    sendResponse(null);
                }
            } else {
                sendResponse(null); // Not a valid page to analyze
            }
        })();
        return true;
    }
});

/**
 * Main analysis pipeline for a given URL.
 * 1. Expands shortened URLs.
 * 2. Gets certificate info.
 * 3. Checks global and user whitelists/blacklists.
 * 4. Checks Google Safe Browsing.
 * 5. Runs local heuristics.
 */
async function analyzeUrlForTab(originalUrl, tabId, domSignals) {
    // Run URL expansion and cert info in parallel
    const [expanded, certInfo] = await Promise.all([
        expandUrl(originalUrl),
        getCertificateInfo(tabId)
    ]);

    const domain = (() => {
        try {
            // Ensure the domain variable is always the extracted domain
            return new URL(expanded).hostname.replace(/^www\./, "");
        } catch {
            return expanded; // Handle invalid URLs
        }
    })();

    // 1. Check global whitelist (no change needed here)
    if (whitelistJson.some(e => (e.domain_root ?.replace(/^www\./, "") === domain) || e.url === expanded)) {
        return {
            url: expanded,
            domain,
            status: "whitelisted",
            score: 0,
            reasons: ["Domain in global whitelist"]
        };
    }

    // 2. Check global blacklist (no change needed here)
    const blMatch = blacklistJson.find(e => (e.domain_root ?.replace(/^www\./, "") === domain) || e.url === expanded);
    if (blMatch) {
        return {
            url: expanded,
            domain,
            status: "blacklisted",
            score: 100,
            reasons: [blMatch.reason || "In global blacklist"]
        };
    }

    // 3. Check user's local lists
    const {
        whitelist,
        blacklist
    } = await getLists();
    
    // This works because we now only store the domain in `addToList`.
    if (whitelist.includes(domain)) { 
        return {
            url: expanded,
            domain,
            status: "whitelisted",
            score: 0,
            reasons: ["Previously marked SAFE by user"]
        };
    }
    if (blacklist.includes(domain)) { // Checks if 'example.com' is in the stored blacklist array
        return {
            url: expanded,
            domain,
            status: "blacklisted",
            score: 100,
            reasons: ["Previously marked UNSAFE by user"]
        };
    }

    // 4. Check Google Safe Browsing API
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

    // 5. Run local heuristics
    const heur = runExplainableHeuristics(expanded, domSignals, certInfo);
    return {
        url: expanded,
        domain,
        status: heur.status,
        score: heur.score,
        reasons: heur.reasons
    };
}

/**
 * Retrieves the user's local whitelist and blacklist from chrome.storage.
 */
async function getLists() {
    const store = await chrome.storage.local.get(["whitelist", "blacklist"]);
    return {
        whitelist: store.whitelist || [],
        blacklist: store.blacklist || []
    };
}

/**
 * Adds a value (domain or URL) to the user's local list.
 */
async function addToList(listName, value) {
    const valueToStore = getDomainFromValue(value);

    const store = await chrome.storage.local.get([listName]);
    const arr = store[listName] || [];
    
    // Check against the normalized valueToStore
    if (!arr.includes(valueToStore)) {
        arr.push(valueToStore);
        await chrome.storage.local.set({
            [listName]: arr
        });
    }
}

/**
 * Expands known URL shorteners by making a HEAD request.
 */
async function expandUrl(url) {
    try {
        const domain = new URL(url).hostname;
        if (!SHORTENERS.includes(domain)) return url; // Not a shortener

        const resp = await fetch(url, {
            method: "HEAD",
            redirect: "manual"
        });

        if (resp.status >= 300 && resp.status < 400 && resp.headers.get("Location")) {
            const loc = resp.headers.get("Location");
            // Resolve relative redirects
            return loc.startsWith("http") ? loc : new URL(loc, url).href;
        }
    } catch {}
    return url; // Return original URL on failure
}

/**
 * Checks a URL against the Google Safe Browsing v4 API.
 */
async function checkSafeBrowsing(url) {
    if (!SAFE_BROWSING_API_KEY) {
        console.warn("SAFE_BROWSING_API_KEY is not set.");
        return {
            malicious: false,
            info: null
        };
    }
    try {
        // Corrected to use the v4 threatMatches:find endpoint
        const apiUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`;
        const resp = await fetch(apiUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                client: {
                    clientId: "ClickDefender",
                    clientVersion: "1.0"
                },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{
                        url
                    }]
                }
            })
        });

        // Check for non-OK response status (e.g., 404, 403, 500)
        if (!resp.ok) {
            const errorText = await resp.text();
            console.error(`Safe Browsing API returned status ${resp.status}: ${errorText}`);
            return {
                malicious: false,
                info: null
            };
        }

        const data = await resp.json();
        if (data && data.matches && data.matches.length > 0) {
            return {
                malicious: true,
                info: data.matches
            };
        }
    } catch (e) {
        console.error("Safe Browsing API check failed unexpectedly:", e);
    }
    return {
        malicious: false,
        info: null
    };
}
// --- AUTO-REMOVE FROM WHITELIST + BLOCK PAGE ---
async function markAsUnsafeAndBlock(value) {
    const domain = getDomainFromValue(value);

    // 1. Remove from whitelist
    const store = await chrome.storage.local.get(["whitelist", "blacklist"]);
    let whitelist = store.whitelist || [];
    let blacklist = store.blacklist || [];

    whitelist = whitelist.filter(item => item !== domain);
    if (!blacklist.includes(domain)) blacklist.push(domain);

    await chrome.storage.local.set({ whitelist, blacklist });

    // 2. Block the active tab immediately
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

    if (tab) {
        chrome.tabs.update(tab.id, { url: chrome.runtime.getURL("blocked.html") });
    }
}
