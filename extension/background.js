// background.js (MV3) - Envelope encryption
// Private key stays in extension storage; decrypt only via extension.

const DEFAULTS = {
  serverBase: "http://localhost:5173",
  orgId: "org_demo",
  token: null,
  user: null,
  rsaPrivateJwk: null, // JWK
  rsaPublicSpkiB64: null
};

function normalizeBase(url) {
  return String(url || "").replace(/\/+$/, "");
}

function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToB64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function bytesToB64url(bytes) {
  return bytesToB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function b64urlToBytes(input) {
  let s = String(input).trim().replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  return b64ToBytes(s);
}

async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(DEFAULTS, (v) => resolve(v || DEFAULTS));
  });
}

async function setSettings(patch) {
  return new Promise((resolve) => {
    chrome.storage.sync.set(patch, resolve);
  });
}

async function apiFetch(path, { serverBase, token, method = "GET", json } = {}) {
  const base = normalizeBase(serverBase);
  const headers = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (json) headers["Content-Type"] = "application/json";

  const res = await fetch(`${base}${path}`, {
    method,
    headers,
    body: json ? JSON.stringify(json) : undefined
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

// ------------------- Keypair management -------------------
async function ensureRsaKeypair(settings) {
  if (settings.rsaPrivateJwk && settings.rsaPublicSpkiB64) return settings;

  // RSA-OAEP for wrapping/unwrapping DEK
  const keypair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["wrapKey", "unwrapKey"]
  );

  const privateJwk = await crypto.subtle.exportKey("jwk", keypair.privateKey);
  const publicSpki = await crypto.subtle.exportKey("spki", keypair.publicKey);

  const publicSpkiB64 = bytesToB64(new Uint8Array(publicSpki));

  const updated = {
    ...settings,
    rsaPrivateJwk: privateJwk,
    rsaPublicSpkiB64: publicSpkiB64
  };

  await setSettings({ rsaPrivateJwk: privateJwk, rsaPublicSpkiB64: publicSpkiB64 });
  return updated;
}

async function importPrivateKeyFromJwk(jwk) {
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["unwrapKey"]
  );
}

async function importPublicKeyFromSpkiB64(spkiB64) {
  const spkiBytes = b64ToBytes(spkiB64);
  return await crypto.subtle.importKey(
    "spki",
    spkiBytes,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["wrapKey"]
  );
}

// ------------------- AES-GCM helpers (DEK) -------------------
async function aesEncrypt(plaintext, aadText = null) {
  const dek = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt"
  ]);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = new TextEncoder().encode(plaintext);

  const alg = { name: "AES-GCM", iv };
  if (aadText) alg.additionalData = new TextEncoder().encode(aadText);

  const ctBuf = await crypto.subtle.encrypt(alg, dek, pt);

  return {
    dek,
    ivB64url: bytesToB64url(iv),
    ciphertextB64url: bytesToB64url(new Uint8Array(ctBuf))
  };
}

async function aesDecrypt(dek, ivB64url, ciphertextB64url, aadText = null) {
  const iv = b64urlToBytes(ivB64url);
  const ct = b64urlToBytes(ciphertextB64url);

  const alg = { name: "AES-GCM", iv };
  if (aadText) alg.additionalData = new TextEncoder().encode(aadText);

  const ptBuf = await crypto.subtle.decrypt(alg, dek, ct);
  return new TextDecoder().decode(new Uint8Array(ptBuf));
}

// ------------------- Wrap / unwrap DEK per user -------------------
async function wrapDekForUser(publicKey, dek) {
  const wrapped = await crypto.subtle.wrapKey("raw", dek, publicKey, { name: "RSA-OAEP" });
  return bytesToB64url(new Uint8Array(wrapped));
}

async function unwrapDekForMe(privateKey, wrappedDekB64url) {
  const wrapped = b64urlToBytes(wrappedDekB64url);

  return await crypto.subtle.unwrapKey(
    "raw",
    wrapped,
    privateKey,
    { name: "RSA-OAEP" },
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

// ------------------- Login + PubKey register -------------------
async function doLogin({ serverBase, orgId, username, password }) {
  const data = await apiFetch("/auth/login", {
    serverBase,
    method: "POST",
    json: { orgId, username, password }
  });

  const settings = await getSettings();
  const merged = {
    ...settings,
    serverBase,
    orgId,
    token: data.token,
    user: data.user
  };

  // Ensure keypair exists and register public key
  const withKeys = await ensureRsaKeypair(merged);

  await apiFetch("/users/me/pubkey", {
    serverBase,
    token: data.token,
    method: "POST",
    json: { publicKeySpkiB64: withKeys.rsaPublicSpkiB64 }
  });

  await setSettings({
    serverBase,
    orgId,
    token: data.token,
    user: data.user,
    rsaPrivateJwk: withKeys.rsaPrivateJwk,
    rsaPublicSpkiB64: withKeys.rsaPublicSpkiB64
  });

  return { ok: true };
}

// ------------------- Encrypt selection in Gmail -------------------
async function encryptSelection(recipientsCsv) {
  const settings = await getSettings();
  if (!settings.token || !settings.user) throw new Error("Please login in popup first.");

  // Ask active tab for selection text
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab");

  const selResp = await chrome.tabs.sendMessage(tab.id, { type: "QM_GET_SELECTION" });
  const plaintext = (selResp?.text || "").trim();
  if (!plaintext) throw new Error("Select text in Gmail compose body first.");

  const serverBase = settings.serverBase;
  const token = settings.token;
  const me = settings.user;

  // Get org users + public keys
  const org = await apiFetch("/org/users", { serverBase, token });

  const requestedNames = (recipientsCsv || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

  // Always include self so sender can decrypt too
  const allowed = new Map();
  allowed.set(me.userId, { userId: me.userId, username: me.username });

  for (const uname of requestedNames) {
    const u = (org.users || []).find(x => x.username === uname);
    if (!u) throw new Error(`Recipient not found: ${uname}`);
    allowed.set(u.userId, u);
  }

  // Require recipients to have public keys
  for (const u of allowed.values()) {
    if (!u.publicKeySpkiB64) throw new Error(`User "${u.username}" has no public key registered (they must login once).`);
  }

  // Encrypt with per-message DEK
  const aad = "gmail";
  const { dek, ivB64url, ciphertextB64url } = await aesEncrypt(plaintext, aad);

  // Wrap DEK per recipient
  const wrappedKeys = {};
  for (const u of allowed.values()) {
    const pub = await importPublicKeyFromSpkiB64(u.publicKeySpkiB64);
    wrappedKeys[u.userId] = await wrapDekForUser(pub, dek);
  }

  // Store message on server
  const created = await apiFetch("/api/messages", {
    serverBase,
    token,
    method: "POST",
    json: {
      iv: ivB64url,
      ciphertext: ciphertextB64url,
      aad,
      wrappedKeys
    }
  });

  const url = created.url;

  // Try insert link into Gmail editor
  await chrome.tabs.sendMessage(tab.id, { type: "QM_INSERT_LINK", url });

  return { ok: true, url };
}

// ------------------- Decrypt link from portal -------------------
async function decryptLink(msgId, origin) {
  const settings = await getSettings();
  if (!settings.token || !settings.user) throw new Error("Extension not logged in. Open popup and login first.");

  const serverBase = settings.serverBase;
  const token = settings.token;

  // Fetch payload (includes wrappedDek for current user only)
  const payload = await apiFetch(`/api/messages/${encodeURIComponent(msgId)}`, { serverBase, token });

  const { iv, ciphertext, aad, wrappedDek } = payload;
  if (!wrappedDek) throw new Error("No wrapped key for you (not an allowed recipient).");

  const s2 = await ensureRsaKeypair(settings);
  const priv = await importPrivateKeyFromJwk(s2.rsaPrivateJwk);

  const dek = await unwrapDekForMe(priv, wrappedDek);
  const plaintext = await aesDecrypt(dek, iv, ciphertext, aad || null);

  return { ok: true, plaintext };
}

// ------------------- Message router -------------------
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "QM_LOGIN") {
        const serverBase = normalizeBase(msg.serverBase);
        const orgId = String(msg.orgId || "").trim();
        const username = String(msg.username || "").trim();
        const password = String(msg.password || "");
        const r = await doLogin({ serverBase, orgId, username, password });
        sendResponse(r);
        return;
      }

      if (msg?.type === "QM_ENCRYPT_SELECTION") {
        const r = await encryptSelection(msg.recipients || "");
        sendResponse(r);
        return;
      }

      if (msg?.type === "QM_DECRYPT_LINK") {
        const r = await decryptLink(msg.msgId, msg.origin);
        sendResponse(r);
        return;
      }

      sendResponse({ ok: false, error: "Unknown message type" });
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();

  return true;
});
