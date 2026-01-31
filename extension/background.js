// background.js (MV3 service worker, type=module)

const EXT = "QuantumMail";
const log = (...args) => console.log(`[${EXT} BG]`, ...args);

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

function parseToken(token) {
  const t = String(token || "").trim();
  const prefix = "qm://v1#";
  const payloadPart = t.startsWith(prefix) ? t.slice(prefix.length) : t;
  if (!payloadPart) throw new Error("Missing token payload");

  const payloadBytes = b64urlToBytes(payloadPart);
  const json = new TextDecoder().decode(payloadBytes);
  const obj = JSON.parse(json);
  if (!obj?.salt || !obj?.iv || !obj?.ct) throw new Error("Invalid token format");
  return obj;
}

async function encryptText(plaintext, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);

  const ptBytes = new TextEncoder().encode(String(plaintext));
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, ptBytes);
  const ct = new Uint8Array(ctBuf);

  const payloadObj = {
    salt: bytesToB64url(salt),
    iv: bytesToB64url(iv),
    ct: bytesToB64url(ct),
  };

  const payloadJson = JSON.stringify(payloadObj);
  const payloadB64url = bytesToB64url(new TextEncoder().encode(payloadJson));
  return `qm://v1#${payloadB64url}`;
}

async function decryptToken(token, passphrase) {
  const { salt, iv, ct } = parseToken(token);
  const key = await deriveKey(passphrase, b64urlToBytes(salt));

  const ptBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64urlToBytes(iv) },
    key,
    b64urlToBytes(ct)
  );

  return new TextDecoder().decode(ptBuf);
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
      if (!passphrase) {
        sendResponse({ ok: false, error: "Missing passphrase" });
        return;
      }

      const tab = await getActiveTab();
      if (!tab?.id) {
        sendResponse({ ok: false, error: "No active tab. Click Gmail tab first." });
        return;
      }
      if (!isSupportedTab(tab)) {
        sendResponse({ ok: false, error: "Open Gmail or Outlook tab, then try again." });
        return;
      }

      // get selected text
      const sel = await sendWithInject(tab.id, { type: "GET_SELECTION" });
      if (sel.lastError) {
        sendResponse({ ok: false, error: sel.lastError.message });
        return;
      }

      const selectedText = String(sel.response?.selectedText || "").trim();
      if (!selectedText) {
        sendResponse({ ok: false, error: "Select text inside the compose message body first." });
        return;
      }

      let replacement = "";
      if (mode === "encrypt") {
        replacement = await encryptText(selectedText, passphrase);
      } else if (mode === "decrypt") {
        replacement = await decryptToken(selectedText, passphrase);
      } else {
        sendResponse({ ok: false, error: "Invalid mode" });
        return;
      }

      const rep = await sendWithInject(tab.id, { type: "REPLACE_SELECTION", text: replacement });
      if (rep.lastError) {
        sendResponse({ ok: false, error: rep.lastError.message });
        return;
      }
      if (!rep.response?.ok) {
        sendResponse({ ok: false, error: rep.response?.error || "Replace failed" });
        return;
      }

      sendResponse({ ok: true, message: mode === "encrypt" ? "Encrypted ✅" : "Decrypted ✅" });
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();

  return true;
});

log("Service worker loaded");
