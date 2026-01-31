// background.js (MV3 service worker, type=module)
// QuantumMail MVP: click icon -> encrypt/decrypt selected text in Gmail/Outlook.

const EXT = "QuantumMail";
const log = (...args) => console.log(`[${EXT} BG]`, ...args);

const SUPPORTED_HOSTS = new Set([
  "mail.google.com",
  "outlook.office.com",
  "outlook.live.com",
]);

function parseUrl(url) {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

function isSupportedTab(tab) {
  const u = parseUrl(tab?.url || "");
  return !!u && u.protocol === "https:" && SUPPORTED_HOSTS.has(u.hostname);
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tabs?.[0] || null;
}

async function findAnySupportedTab() {
  const matches = await chrome.tabs.query({
    url: [
      "https://mail.google.com/*",
      "https://outlook.office.com/*",
      "https://outlook.live.com/*"
    ]
  });
  return matches?.find((t) => t?.id) || null;
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
  // Try once
  let res = await sendToTab(tabId, message);

  // If receiver missing, inject and retry
  if (res?.lastError?.message?.includes("Receiving end does not exist")) {
    log("Receiver missing; injecting content.js then retrying...");
    await ensureContentScript(tabId);
    res = await sendToTab(tabId, message);
  }

  return res;
}

async function pickTargetTab() {
  const active = await getActiveTab();
  if (active?.id && isSupportedTab(active)) return active;

  const any = await findAnySupportedTab();
  if (any?.id && isSupportedTab(any)) return any;

  return null;
}

// Clicking the toolbar icon runs encrypt/decrypt on selection
chrome.action.onClicked.addListener(async () => {
  try {
    const tab = await pickTargetTab();
    if (!tab?.id) {
      log("No Gmail/Outlook tab found. Open Gmail/Outlook and try again.");
      return;
    }

    // Ask content script what is selected
    const selRes = await sendWithInject(tab.id, { type: "GET_SELECTION" });
    if (selRes.lastError) {
      log("GET_SELECTION error:", selRes.lastError.message);
      return;
    }

    const selectedText = (selRes.response?.selectedText || "").trim();
    if (!selectedText) {
      log("Nothing selected. Highlight text/token in the compose area first.");
      return;
    }

    // Ask for passphrase (MVP). Note: prompt is available in SW in most cases,
    // but if it is blocked in your environment, tell me and I'll add a tiny popup.
    const passphrase = globalThis.prompt?.("QuantumMail passphrase (same for decrypt):", "");
    if (!passphrase) {
      log("No passphrase entered.");
      return;
    }

    const isToken = selectedText.startsWith("qm://v1#");

    if (isToken) {
      // DECRYPT selection -> replace selection with plaintext
      const { plaintext } = await decryptToken(selectedText, passphrase);
      const rep = await sendWithInject(tab.id, {
        type: "REPLACE_SELECTION",
        text: plaintext,
      });

      if (rep.lastError) log("REPLACE_SELECTION error:", rep.lastError.message);
      else log("Decrypted + replaced selection.");
    } else {
      // ENCRYPT selection -> replace selection with token
      const token = await encryptText(selectedText, passphrase);
      const rep = await sendWithInject(tab.id, {
        type: "REPLACE_SELECTION",
        text: token,
      });

      if (rep.lastError) log("REPLACE_SELECTION error:", rep.lastError.message);
      else log("Encrypted + replaced selection.");
    }
  } catch (e) {
    log("onClicked exception:", e);
  }
});

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
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 200_000,
      hash: "SHA-256",
    },
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
  return obj; // {salt, iv, ct}
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

  const saltBytes = b64urlToBytes(salt);
  const ivBytes = b64urlToBytes(iv);
  const ctBytes = b64urlToBytes(ct);

  const key = await deriveKey(passphrase, saltBytes);

  const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivBytes }, key, ctBytes);
  const plaintext = new TextDecoder().decode(ptBuf);

  return { plaintext };
}

log("Service worker loaded");
