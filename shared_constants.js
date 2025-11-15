// shared_constants.js

// Common URL shortener domains
export const SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "buff.ly"
];

// Top-Level Domains often associated with spam or phishing
export const SUSPICIOUS_TLDS = [
  "zip",
  "mov",
  "tk",
  "gq",
  "ml",
  "cf",
  "ga"
];

// Common brands to check for typosquatting
export const BRANDS = [
  "google",
  "facebook",
  "apple",
  "microsoft",
  "amazon",
  "paypal",
  "netflix",
  "instagram",
  "whatsapp",
  "twitter",
  "bankofamerica",
  "chase",
  "wellsfargo",
  "hsbc",
  "citibank"
];

// Keywords often found in phishing URLs or page content
export const SUSPICIOUS_WORDS = [
  "login",
  "verify",
  "update",
  "password",
  "account",
  "billing",
  "secure",
  "confirm",
  "unlock",
  "limited",
  "urgent"
];