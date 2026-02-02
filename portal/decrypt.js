// portal/decrypt.js (Enterprise Model B) - FULL
// - Login to get Bearer token
// - Fetch message + key material
// - Safe base64/base64url decoding (prevents atob crashes)
// - AES-GCM decrypt in browser

// -------------------- Base64url helpers (SAFE) --------------------
function toBase64(input) {
  if (typeof input !== "string") {
    throw new Error(`Expected string, got ${typeof input}`);
  }

  // Trim + remove accidental whitespace/newlines
  let s = input.trim().replace(/\s+/g, "");

  // Strip accidental quotes
  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("'") && s.endsWith("'"))
  ) {
    s = s.slice(1, -1);
  }

  // base64url -> base64
  s = s.replace(/-/g, "+").replace(/_/g, "/");

  // padding
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);

  // validate charset
  if (!/^[A-Za-z0-9+/=]+$/.test(s)) {
    throw new Error("Contains invalid base64 characters");
  }

  return s;
}

function b64ToBytesStrict(label, input) {
  if (input == null) {
    throw new Error(`${label} is missing (null/undefined)`);
  }

  const raw = String(input);
  const b64 = toBase64(raw);

  try {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  } catch {
    const preview = raw.slice(0, 60);
    throw new Error(`${label} is not valid base64/base64url. Preview="${preview}"`);
  }
}

function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

// -------------------- URL parsing --------------------
function getIdFromUrl() {
  const p = window.location.pathname;
  const parts = p.split("/").filter(Boolean);

  // handles /m/<id>
  const mIndex = parts.indexOf("m");
  if (mIndex >= 0 && parts[mIndex + 1]) return parts[mIndex + 1];

  // fallback: last segment
  return parts[parts.length - 1] || "";
}

function apiBase() {
  return window.location.origin;
}

// -------------------- UI helpers --------------------
function setStatus(msg, ok = false) {
  const el = document.getElementById("status");
  if (!el) return;
  el.textContent = msg;
  el.className = ok ? "ok" : "muted";
}

function show(id, on) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.display = on ? "" : "none";
}

function setError(msg) {
  const el = document.getElementById("err");
  if (!el) return;
  el.textContent = msg || "";
}

function setMeta(msg) {
  const el = document.getElementById("meta");
  if (!el) return;
  el.textContent = msg || "";
}

function setPlaintext(msg) {
  const el = document.getElementById("plaintext");
  if (!el) return;
  el.textContent = msg || "";
}

// -------------------- Session persistence --------------------
function getSavedSession() {
  try {
    const raw = localStorage.getItem("qm_session");
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function saveSession(session) {
  localStorage.setItem("qm_session", JSON.stringify(session));
}

function clearSession() {
  localStorage.removeItem("qm_session");
}

// -------------------- API calls --------------------
async function login(orgId, username, password) {
  const r = await fetch(`${apiBase()}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ orgId, username, password })
  });

  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data?.error || `Login failed (${r.status})`);
  if (!data.token) throw new Error("Login response missing token");
  return data;
}

async function fetchJson(url, token) {
  const r = await fetch(url, {
    headers: { Authorization: `Bearer ${token}` }
  });

  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data?.error || `Request failed (${r.status})`);
  return data;
}

// -------------------- Crypto: AES-GCM decrypt --------------------
async function decryptAesGcm({ keyB64, ivB64, ctB64, aad }) {
  const keyBytes = b64ToBytesStrict("keyB64", keyB64);
  const iv = b64ToBytesStrict("iv", ivB64);
  const ct = b64ToBytesStrict("ciphertext", ctB64);

  if (keyBytes.length !== 32) {
    throw new Error(`keyB64 decoded to ${keyBytes.length} bytes, expected 32`);
  }

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const alg = { name: "AES-GCM", iv };

  // ✅ AAD is UTF-8 text (ex: "gmail"), not base64
  if (aad) {
    alg.additionalData = new TextEncoder().encode(aad);
  }

  const ptBuf = await crypto.subtle.decrypt(alg, cryptoKey, ct);
  return new TextDecoder().decode(new Uint8Array(ptBuf));
}


async function loadAndDecrypt(msgId, token) {
  const msg = await fetchJson(`${apiBase()}/api/messages/${msgId}`, token);

  // Guard: if auth failed or message missing fields, show useful error
  if (!msg?.iv || !msg?.ciphertext || !msg?.keyVersion) {
    throw new Error("Message payload missing iv/ciphertext/keyVersion (auth or fetch failed).");
  }

  const km = await fetchJson(`${apiBase()}/keys/${msg.keyVersion}/material`, token);
  if (!km?.keyB64) throw new Error("Key material response missing keyB64");

  // Helpful debug (won't break anything)
  console.log("Decrypt inputs:", {
    id: msgId,
    keyVersion: msg.keyVersion,
    ivPreview: String(msg.iv).slice(0, 20),
    ctPreview: String(msg.ciphertext).slice(0, 20),
    keyPreview: String(km.keyB64).slice(0, 20),
    aadPreview: msg.aad ? String(msg.aad).slice(0, 20) : null
  });

  const plaintext = await decryptAesGcm({
    keyB64: km.keyB64,
    ivB64: msg.iv,
    ctB64: msg.ciphertext,
    aad: msg.aad
  });

  return { msg, plaintext };
}

// -------------------- Page init + handlers --------------------
const msgId = getIdFromUrl();

const orgIdInput = document.getElementById("orgId");
const userInput = document.getElementById("username");
const passInput = document.getElementById("password");

const btnLogin = document.getElementById("btnLogin");
const btnClear = document.getElementById("btnClear");
const btnDecrypt = document.getElementById("btnDecrypt");
const btnLogout = document.getElementById("btnLogout");

btnClear?.addEventListener("click", () => {
  clearSession();
  location.reload();
});

btnLogout?.addEventListener("click", () => {
  clearSession();
  location.reload();
});

btnLogin?.addEventListener("click", async () => {
  try {
    setError("");
    setStatus("Signing in…");

    const orgId = String(orgIdInput?.value || "").trim();
    const username = String(userInput?.value || "").trim();
    const password = String(passInput?.value || "");

    const data = await login(orgId, username, password);
    saveSession({ token: data.token, orgId });

    setStatus("Signed in. Ready to decrypt.", true);
    show("loginBox", false);
    show("resultBox", true);
  } catch (e) {
    setStatus("Sign in failed.");
    setError(String(e?.message || e));
  }
});

btnDecrypt?.addEventListener("click", async () => {
  try {
    setError("");
    setPlaintext("(decrypting...)");
    setStatus("Loading message…");

    const session = getSavedSession();
    if (!session?.token) {
      setStatus("Please sign in.");
      show("loginBox", true);
      show("resultBox", false);
      return;
    }

    const { msg, plaintext } = await loadAndDecrypt(msgId, session.token);

    setStatus("Decrypted ✅", true);
    setMeta(`Message: ${msgId} • KeyVersion: ${msg.keyVersion} • Created: ${msg.createdAt}`);
    setPlaintext(plaintext);
  } catch (e) {
    setStatus("Failed to load/decrypt.");
    setPlaintext("(not decrypted)");
    setError(String(e?.message || e));
  }
});

(async () => {
  if (!msgId) {
    setStatus("Invalid link: missing message id.");
    show("loginBox", false);
    show("resultBox", false);
    return;
  }

  const saved = getSavedSession();
  if (saved?.token && saved?.orgId) {
    setStatus(`Session found for org "${saved.orgId}".`, true);
    show("loginBox", false);
    show("resultBox", true);
    // Do NOT auto-decrypt (keeps control explicit)
    return;
  }

  // No session: show login
  setStatus("Sign in to decrypt.");
  show("loginBox", true);
  show("resultBox", false);

  // default org
  if (orgIdInput) orgIdInput.value = "org_demo";
})();
