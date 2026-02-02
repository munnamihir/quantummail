// QuantumMail Enterprise - background (MV3 service worker)
// - Stores settings + JWT
// - Provides API helpers + AES-GCM crypto helpers (WebCrypto)
// - Content script calls these via chrome.runtime.sendMessage

const DEFAULTS = {
  apiBase: "http://localhost:5173",
  orgId: "org_demo"
};

function normalizeBase(url) {
  return String(url || "").replace(/\/+$/, "");
}

function storageGet(keysObj) {
  return new Promise((resolve) => chrome.storage.sync.get(keysObj, (v) => resolve(v || keysObj)));
}
function storageSet(patch) {
  return new Promise((resolve, reject) =>
    chrome.storage.sync.set(patch, () => {
      const err = chrome.runtime.lastError;
      if (err) reject(err);
      else resolve();
    })
  );
}

async function getSettings() {
  const v = await storageGet(DEFAULTS);
  return { ...DEFAULTS, ...v, apiBase: normalizeBase(v.apiBase) };
}

async function getAuthToken() {
  const { token } = await storageGet({ token: null });
  return token || null;
}

// ---------- Base64url helpers ----------
function bytesToB64url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return b64;
}
function b64urlToBytes(b64url) {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ---------- Crypto ----------
async function importAesKeyFromB64url(keyB64url) {
  const raw = b64urlToBytes(keyB64url);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function aesGcmEncrypt(cryptoKey, plaintext, aadStr = "") {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const pt = enc.encode(String(plaintext));

  const aad = aadStr ? enc.encode(aadStr) : null;

  const ctBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad || undefined },
    cryptoKey,
    pt
  );

  return {
    iv: bytesToB64url(iv),
    ciphertext: bytesToB64url(new Uint8Array(ctBuf))
  };
}

async function aesGcmDecrypt(cryptoKey, ivB64url, ciphertextB64url, aadStr = "") {
  const iv = b64urlToBytes(ivB64url);
  const ct = b64urlToBytes(ciphertextB64url);
  const enc = new TextEncoder();
  const aad = aadStr ? enc.encode(aadStr) : null;

  const ptBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad || undefined },
    cryptoKey,
    ct
  );

  return new TextDecoder().decode(ptBuf);
}

// ---------- API ----------
async function apiFetch(path, { method = "GET", jsonBody = null } = {}) {
  const { apiBase } = await getSettings();
  const token = await getAuthToken();

  const headers = { "Accept": "application/json" };
  if (jsonBody) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${apiBase}${path}`, {
    method,
    headers,
    body: jsonBody ? JSON.stringify(jsonBody) : undefined
  });

  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }

  if (!res.ok) {
    const msg = data?.error || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

// cache CryptoKey by version in SW memory
const keyCache = new Map(); // version -> CryptoKey

async function getActiveKeyVersion() {
  const data = await apiFetch("/keys/active");
  return data.version;
}
async function getKeyMaterial(version) {
  if (keyCache.has(version)) return keyCache.get(version);
  const data = await apiFetch(`/keys/${version}/material`);
  const key = await importAesKeyFromB64url(data.keyB64);
  keyCache.set(version, key);
  return key;
}

// ---------- Message flow (Model B) ----------
async function encryptAndStoreMessage(plaintext, aadStr = "") {
  const version = await getActiveKeyVersion();
  const key = await getKeyMaterial(version);

  const enc = await aesGcmEncrypt(key, plaintext, aadStr);
  const saved = await apiFetch("/api/messages", {
    method: "POST",
    jsonBody: {
      keyVersion: version,
      iv: enc.iv,
      ciphertext: enc.ciphertext,
      aad: aadStr || null
    }
  });

  return { url: saved.url, id: saved.id, keyVersion: version };
}

function parseMessageIdFromLink(link) {
  try {
    const u = new URL(link);
    // accept /m/<id> or /portal/m/<id>
    const parts = u.pathname.split("/").filter(Boolean);
    const mIndex = parts.indexOf("m");
    if (mIndex >= 0 && parts[mIndex + 1]) return parts[mIndex + 1];
  } catch {}
  // fallback: raw id
  const m = String(link || "").match(/\/m\/([A-Za-z0-9_-]{6,})/);
  return m ? m[1] : null;
}

async function fetchAndDecryptMessageById(id) {
  const msg = await apiFetch(`/api/messages/${id}`);
  const key = await getKeyMaterial(msg.keyVersion);
  const pt = await aesGcmDecrypt(key, msg.iv, msg.ciphertext, msg.aad || "");
  return { plaintext: pt, keyVersion: msg.keyVersion, createdAt: msg.createdAt };
}

// ---------- Auth ----------
async function login({ orgId, username, password }) {
  const { apiBase } = await getSettings();
  const res = await fetch(`${apiBase}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify({ orgId, username, password })
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);

  await storageSet({ token: data.token, orgId });
  // clear cache on new login
  keyCache.clear();
  return data.user;
}

async function logout() {
  await storageSet({ token: null });
  keyCache.clear();
}

// ---------- Message router ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "qm_get_settings") {
        const s = await getSettings();
        const token = await getAuthToken();
        sendResponse({ ok: true, settings: s, isAuthed: !!token });
        return;
      }
      if (msg?.type === "qm_set_settings") {
        const patch = {};
        if (typeof msg.apiBase === "string") patch.apiBase = normalizeBase(msg.apiBase);
        if (typeof msg.orgId === "string") patch.orgId = msg.orgId;
        await storageSet(patch);
        sendResponse({ ok: true });
        return;
      }
      if (msg?.type === "qm_login") {
        const user = await login(msg);
        sendResponse({ ok: true, user });
        return;
      }
      if (msg?.type === "qm_logout") {
        await logout();
        sendResponse({ ok: true });
        return;
      }
      if (msg?.type === "qm_encrypt_store") {
        const result = await encryptAndStoreMessage(msg.plaintext || "", msg.aad || "");
        sendResponse({ ok: true, result });
        return;
      }
      if (msg?.type === "qm_decrypt_link") {
        const id = parseMessageIdFromLink(msg.link || "");
        if (!id) throw new Error("Could not parse message id from link");
        const result = await fetchAndDecryptMessageById(id);
        sendResponse({ ok: true, result });
        return;
      }

      throw new Error("Unknown request");
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();

  return true; // keep channel open for async
});
