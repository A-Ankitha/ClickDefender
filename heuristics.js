import {
  SHORTENERS,
  SUSPICIOUS_TLDS,
  BRANDS,
  SUSPICIOUS_WORDS
} from './shared_constants.js';

// Extract base domain (e.g., amazon.com, paypal.com)
function getBaseDomain(url) {
  try {
    const hostname = new URL(url).hostname;
    const parts = hostname.split(".");
    return parts.slice(-2).join(".");
  } catch {
    return "";
  }
}

/**
 * Calculates the Levenshtein distance between two strings.
 * Used for typosquatting detection.
 */
function levenshtein(a, b) {
  a = (a || "").toLowerCase();
  b = (b || "").toLowerCase();
  const m = a.length,
    n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  const dp = Array.from({
    length: m + 1
  }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1, // deletion
        dp[i][j - 1] + 1, // insertion
        dp[i - 1][j - 1] + cost // substitution
      );
    }
  }
  return dp[m][n];
}

/**
 * Calculates the Shannon entropy of a string.
 * Used to detect random, algorithmically-generated domains.
 */
function shannonEntropy(str) {
  if (!str) return 0;
  const map = {};
  for (const c of str) map[c] = (map[c] || 0) + 1;
  const len = str.length;
  let H = 0;
  for (const k in map) {
    const p = map[k] / len;
    H -= p * Math.log2(p);
  }
  return H;
}
function detectBrandImpersonation(url) {
  let hostname = "";
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch {
    return { flag: false };
  }

  const baseDomain = getBaseDomain(url).toLowerCase();

  for (const brand of BRANDS) {
    const b = brand.toLowerCase();

    // If real domain includes brand → NOT a phishing attempt
    if (baseDomain.includes(b)) continue;

    // If hostname has the brand somewhere else → suspicious
    if (hostname.includes(b)) {
      return { flag: true, brand: b };
    }
  }

  return { flag: false };
}

/**
 * Runs all heuristic checks on a URL and DOM signals.
 * Returns a score, a list of reasons, and a status.
 */
export function runExplainableHeuristics(url, domSignals, certInfo) {
  const base = 30; // Start with a neutral score
  let score = base;
  const reasons = [];

  if (!url) {
    return {
      score,
      reasons: ["No URL"],
      status: "unknown"
    };
  }

  try {
    const u = new URL(url);
    const host = u.hostname.replace(/^www\./, "");
    const pathQuery = (u.pathname || "") + (u.search || "");
    const tld = host.split(".").pop() || "";
    const lower = String(url).toLowerCase();

    // Protocol check
    if (lower.startsWith("https://")) {
      score -= 10;
      reasons.push("Uses HTTPS (-10)");
      // SSL Certificate check
      if (certInfo && certInfo.validityDurationDays) {
        if (certInfo.validityDurationDays <= 95) {
          score += 15;
          reasons.push(`Short SSL certificate validity (${certInfo.validityDurationDays} days) (+15)`);
        } else if (certInfo.validityDurationDays >= 365) {
          score -= 10;
          reasons.push(`Long SSL certificate validity (${certInfo.validityDurationDays} days) (-10)`);
        }
      }
    } else if (lower.startsWith("http://")) {
      score += 10;
      reasons.push("No HTTPS (+10)");
    }

    // URL length check
    if (url.length > 75) {
      score += 12;
      reasons.push("Long URL (>75) (+12)");
    }

    // Entropy check
    const ent = shannonEntropy(host + pathQuery);
    if (ent >= 4.0) {
      score += 10;
      reasons.push("High URL entropy (+10)");
    }

    // Subdomain check
    const dotCount = (host.match(/\./g) || []).length;
    if (dotCount >= 3) {
      score += 10;
      reasons.push("Many subdomains (+10)");
    }

    // Hyphen check
    if (host.includes("-")) {
      score += 6;
      reasons.push("Hyphen in domain (+6)");
    }

    // Brand Impersonation check
    const brandCheck = detectBrandImpersonation(url);
    if (brandCheck.flag) {
      score += 25;
      reasons.push(`Brand impersonation suspected: '${brandCheck.brand}' (+25)`);
    }

    // Shortener check
    if (SHORTENERS.includes(host)) {
      score += 18;
      reasons.push("URL shortener (+18)");
    }

    // TLD check
    if (SUSPICIOUS_TLDS.includes(tld)) {
      score += 6;
      reasons.push(`Suspicious TLD .${tld} (+6)`);
    }

    // '@' symbol check
    if (lower.includes("@")) {
      score += 30;
      reasons.push("Contains '@' (+30)");
    }

    // Symbol density check
    const symbolDensity = (pathQuery.match(/[^\w/]/g) || []).length / Math.max(1, pathQuery.length);
    if (symbolDensity > 0.25 && pathQuery.length > 20) {
      score += 10;
      reasons.push("High symbol density in path/query (+10)");
    }

    // Punycode check (IDN homograph attack)
    if (host.includes("xn--")) {
      score += 18;
      reasons.push("IDN/punycode domain (+18)");
    }

    // Suspicious keyword check
    const kwHits = SUSPICIOUS_WORDS.filter(k => lower.includes(k));
    if (kwHits.length >= 2) {
      score += 10;
      reasons.push(`Suspicious keywords in URL: ${kwHits.slice(0,3).join(", ")} (+10)`);
    } else if (kwHits.length === 1) {
      score += 6;
      reasons.push(`Keyword '${kwHits[0]}' in URL (+6)`);
    }

  } catch (e) {
    console.error("URL parsing failed:", e);
    score += 5;
    reasons.push("Malformed URL (+6)");
  }

  // DOM signal checks (from content.js)
  if (domSignals && typeof domSignals === "object") {

      // --- Password Forms ---
      if (domSignals.passwordForms > 0) {
          score += 6;
          reasons.push("Password form present (+6)");
      }

      // --- Body Keyword Check with Context ---
      if (domSignals.bodyKeywords && domSignals.bodyKeywords.length > 0) {
          const matchedThreats = domSignals.bodyKeywords.filter(k =>
              SUSPICIOUS_WORDS.includes(k.toLowerCase())
          );

          // Penalize ONLY if a real phishing-context word is found
          if (matchedThreats.length > 0) {
              score += 4;
              reasons.push(
                  `Suspicious keyword context detected: ${matchedThreats.join(", ")} (+4)`
              );
          }
      }


      // --- Suspicious External Form Action ---
      if (domSignals.suspiciousFormActions && domSignals.suspiciousFormActions.length > 0) {
          score += 30;
          reasons.push(
              `Form submits data to external domain: ${domSignals.suspiciousFormActions[0]} (+30)`
          );
      }

      // --- Hidden Elements ---
      if (domSignals.hiddenElements && domSignals.hiddenElements > 20) {
          score += 10;
          reasons.push(
              `High number of hidden elements (${domSignals.hiddenElements}) (+10)`
          );
      }
  }


  // Final score clamping
  score = Math.min(100, Math.max(0, score));

  // Determine status
  let status = "unknown";
  if (score <= 25) status = "safe";
  else if (score >= 85) status = "dangerous";
  else status = "suspicious";

  return {
    score,
    reasons,
    status
  };
}
