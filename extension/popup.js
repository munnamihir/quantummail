import {
  normalizeBase,
  getSession,
  setSession,
  clearSession,
  ensureKeypairAndRegister,
  parseRecipients
} from "./qm.js";

const $ = (id) => document.getElementById(id);

function setStatus(text) { $("status").textContent = text; }
function ok(msg) { $("ok").textContent = msg || ""; }
function err(msg) { $("err").textContent = msg || ""; }

async function sendBg(type, payload = {}) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ type, ...payload }, (resp) => resolve(resp));
  });
}

async function login() {
  ok(""); err("");
  const serverBase = normalizeBase($("serverBase").value.trim());
  const orgId = $("orgId").value.trim();
  const username = $("username").value.trim();
  const password = $("password").value;

  if (!serverBase || !orgId || !username || !password) {
    throw new Error("serverBase, orgId, username, password required");
  }

  const resp = await sendBg("QM_LOGIN", { serverBase, orgId, username, password });
  if (!resp?.ok) throw new Error(resp?.error || "Login failed");

  // Ensure RSA keys exist and register public key
  const s = await getSession();
  await ensureKeypairAndRegister(s.serverBase, s.token);

  ok("Logged in + public key registered ✅");
  setStatus(`${username}@${orgId}`);
}

async function logout() {
  ok(""); err("");
  await clearSession();
  setStatus("Signed out");
  ok("Logged out.");
}

async function encryptSelected() {
  ok(""); err("");
  const s = await getSession();
  if (!s?.token) throw new Error("Please login first.");

  const recipients = parseRecipients($("recipients").value);
  if (!recipients.length) throw new Error("Enter at least 1 recipient username.");

  const resp = await sendBg("QM_ENCRYPT_SELECTION", { recipients });
  if (!resp?.ok) throw new Error(resp?.error || "Encrypt failed");

  ok("Link inserted ✅");
}

async function init() {
  const s = await getSession();
  if (s?.token) setStatus(`${s.user?.username || "user"}@${s.user?.orgId || "org"}`);
  else setStatus("Signed out");

  // Defaults helpful in Codespaces
  if (!$("serverBase").value) {
    $("serverBase").value = normalizeBase(window.location.origin);
  }
  if (!$("orgId").value) $("orgId").value = "org_demo";
}

$("btnLogin").addEventListener("click", () => login().catch(e => err(e.message || String(e))));
$("btnLogout").addEventListener("click", () => logout().catch(e => err(e.message || String(e))));
$("btnEncrypt").addEventListener("click", () => encryptSelected().catch(e => err(e.message || String(e))));

init();
