// background.js (MV3 service worker, type=module)
// QuantumMail MVP: encrypt selection -> share link (Model A)
// decrypt selection -> plaintext (works for qm:// token or the share link)

const EXT = "QuantumMail";
const log = (...args) => console.log(`[${EXT} BG]`, ...args);

// CHANGE THIS later to your real domain, e.g. https://quantummail.app
const SHARE_BASE = "http://localhost:5173";

// Gmail/Outlook support
const SUPPORTED_HOSTS = new Set([
  "mail.google.com",
  "outlook.office.com",
  "outlook.live.com",
]);

function parseUrl(url) {
  try { return new URL(url); } catch { return null; }
}

function isSupportedTab(tab) {
  const u = parseUrl(tab?.url || "");
  return !!u && u.protocol === "https:" && SUPPORTED_HOSTS.has(u.hostname);
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tabs?.[0] || null;
}

async function ensureContentScript(tabId) {
  await chrome.scripting.executeScript({
    target: { tabId },
    files: ["content.js"],
  });
}

function sendToTab(tabId, message) {
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, message, (response) => {
      resolve({ response, lastError: chrome.runtime.lastError });
    });
  });
}

async function sendWithInject(tabId, message) {
  let res = await sendToTab(tabId, message);
  if (res?.lastError?.message?.includes("Receiving end does not exist")) {
    log("Receiver missing; injecting content.js then retrying...");
    await ensureContentScript(tabId);
    res = await sendToTab(tabId, message);
  }
  return res;
}

// ---------- CRYPTO (AES-GCM + PBKDF2) ----------
function b64urlToBytes(b64url) {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToB64url(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function deriveKey(passphrase, saltBytes) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: 200_000, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function makePayloadObject({ saltBytes, ivBytes, ctBytes }) {
  return {
    salt: bytesToB64url(saltBytes),
    iv: bytesToB64url(ivBytes),
    ct: bytesToB64url(ctBytes),
  };
}

function payloadObjToB64url(payloadObj) {
  const payloadJson = JSON.stringify(payloadObj);
  return bytesToB64url(new TextEncoder().encode(payloadJson));
}

// Accepts either:
// - qm://v1#<payload>
// - http(s)://.../#qm=<payload>
// - just <payload>
function extractPayloadB64url(input) {
  const s = String(input || "").trim();
  if (!s) throw new Error("Empty input");

  // qm:// token
  if (s.startsWith("qm://v1#")) {
    const payload = s.slice("qm://v1#".length).trim();
    if (!payload) throw new Error("Missing qm payload");
    return payload;
  }

  // share link
  if (s.startsWith("http://") || s.startsWith("https://")) {
    const u = new URL(s);
    // use fragment, not query
    const hash = (u.hash || "").replace(/^#/, "");
    const params = new URLSearchParams(hash);
    const payload = params.get("qm");
    if (!payload) throw new Error("No #qm= payload in link");
    return payload;
  }

  // maybe the payload itself
  return s;
}

async function encryptToPayloadB64url(plaintext, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);

  const ptBytes = new TextEncoder().encode(String(plaintext));
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, ptBytes);
  const ct = new Uint8Array(ctBuf);

  const payloadObj = makePayloadObject({ saltBytes: salt, ivBytes: iv, ctBytes: ct });
  return payloadObjToB64url(payloadObj);
}

function payloadB64urlToObj(payloadB64url) {
  const payloadBytes = b64urlToBytes(payloadB64url);
  const json = new TextDecoder().decode(payloadBytes);
  const obj = JSON.parse(json);
  if (!obj?.salt || !obj?.iv || !obj?.ct) throw new Error("Invalid payload");
  return obj;
}

async function decryptFromPayloadB64url(payloadB64url, passphrase) {
  const obj = payloadB64urlToObj(payloadB64url);
  const key = await deriveKey(passphrase, b64urlToBytes(obj.salt));

  const ptBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64urlToBytes(obj.iv) },
    key,
    b64urlToBytes(obj.ct)
  );
  return new TextDecoder().decode(ptBuf);
}

function buildShareLink(payloadB64url) {
  // Payload stays in fragment so server never receives it
  return `${SHARE_BASE}/#qm=${payloadB64url}`;
}

// ---------- MAIN FLOW CALLED FROM POPUP ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type !== "RUN_SELECTION") {
        sendResponse({ ok: false, error: "Unknown message" });
        return;
      }

      const mode = msg.mode; // "encrypt" | "decrypt"
      const passphrase = String(msg.passphrase || "");
      if (!passphrase) return sendResponse({ ok: false, error: "Missing passphrase" });

      const tab = await getActiveTab();
      if (!tab?.id) return sendResponse({ ok: false, error: "No active tab. Click Gmail tab first." });
      if (!isSupportedTab(tab)) return sendResponse({ ok: false, error: "Open Gmail/Outlook, then try again." });

      // get selected text
      const sel = await sendWithInject(tab.id, { type: "GET_SELECTION" });
      if (sel.lastError) return sendResponse({ ok: false, error: sel.lastError.message });

      const selectedText = String(sel.response?.selectedText || "").trim();
      if (!selectedText) return sendResponse({ ok: false, error: "Select text/link/token in the email first." });

      let replacement = "";

      if (mode === "encrypt") {
        // Encrypt plaintext -> payload -> share link
        const payloadB64url = await encryptToPayloadB64url(selectedText, passphrase);
        replacement = buildShareLink(payloadB64url);
      } else if (mode === "decrypt") {
        // Decrypt selected token/link -> plaintext
        const payloadB64url = extractPayloadB64url(selectedText);
        replacement = await decryptFromPayloadB64url(payloadB64url, passphrase);
      } else {
        return sendResponse({ ok: false, error: "Invalid mode" });
      }

      // Replace selection in compose OR read view (content.js handles both)
      const rep = await sendWithInject(tab.id, { type: "REPLACE_SELECTION", text: replacement });
      if (rep.lastError) return sendResponse({ ok: false, error: rep.lastError.message });
      if (!rep.response?.ok) return sendResponse({ ok: false, error: rep.response?.error || "Replace failed" });

      sendResponse({
        ok: true,
        message:
          mode === "encrypt"
            ? "Encrypted → link inserted ✅ (send it)"
            : "Decrypted ✅"
      });
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();

  return true;
});

log("Service worker loaded");
