async function send(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, resolve));
}

const statusEl = document.getElementById("status");
const apiBaseEl = document.getElementById("apiBase");
const orgIdEl = document.getElementById("orgId");
const userEl = document.getElementById("username");
const passEl = document.getElementById("password");

const authBlock = document.getElementById("authBlock");
const authedBlock = document.getElementById("authedBlock");

const save1 = document.getElementById("saveSettings");
const save2 = document.getElementById("saveSettings2");
const loginBtn = document.getElementById("loginBtn");
const logoutBtn = document.getElementById("logoutBtn");

const encryptSelectionBtn = document.getElementById("encryptSelectionBtn");
const linkInput = document.getElementById("linkInput");
const decryptBtn = document.getElementById("decryptBtn");
const plaintextEl = document.getElementById("plaintext");

function setStatus(text, kind="muted") {
  statusEl.className = "status " + kind;
  statusEl.textContent = text;
}

async function load() {
  const resp = await send({ type: "qm_get_settings" });
  if (!resp?.ok) return setStatus(resp?.error || "Failed to load", "err");

  apiBaseEl.value = resp.settings.apiBase || "";
  orgIdEl.value = resp.settings.orgId || "";

  if (resp.isAuthed) {
    authBlock.style.display = "none";
    authedBlock.style.display = "block";
    setStatus("Authenticated ✅", "ok");
  } else {
    authBlock.style.display = "block";
    authedBlock.style.display = "none";
    setStatus("Not logged in", "muted");
  }
}

async function saveSettings() {
  const r = await send({
    type: "qm_set_settings",
    apiBase: apiBaseEl.value.trim(),
    orgId: orgIdEl.value.trim()
  });
  if (!r?.ok) return setStatus(r?.error || "Save failed", "err");
  setStatus("Settings saved ✅", "ok");
}

save1.addEventListener("click", saveSettings);
save2.addEventListener("click", saveSettings);

loginBtn.addEventListener("click", async () => {
  setStatus("Logging in...", "muted");
  try {
    await saveSettings();
    const r = await send({
      type: "qm_login",
      orgId: orgIdEl.value.trim(),
      username: userEl.value.trim(),
      password: passEl.value
    });
    if (!r?.ok) throw new Error(r?.error || "Login failed");
    passEl.value = "";
    await load();
  } catch (e) {
    setStatus(String(e.message || e), "err");
  }
});

logoutBtn.addEventListener("click", async () => {
  const r = await send({ type: "qm_logout" });
  if (!r?.ok) return setStatus(r?.error || "Logout failed", "err");
  plaintextEl.value = "";
  await load();
});

encryptSelectionBtn.addEventListener("click", async () => {
  setStatus("Encrypting selection...", "muted");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return setStatus("No active tab", "err");

  // Ask content script to return selected text from compose
  const selected = await chrome.tabs.sendMessage(tab.id, { type: "qm_get_selected_text" })
    .catch(() => null);

  if (!selected?.ok) return setStatus(selected?.error || "Select text in Gmail compose first", "err");

  const plaintext = selected.text || "";
  if (!plaintext.trim()) return setStatus("Selection is empty", "err");

  const enc = await send({ type: "qm_encrypt_store", plaintext, aad: "gmail" });
  if (!enc?.ok) return setStatus(enc?.error || "Encrypt failed", "err");

  const url = enc.result.url;

  // Replace selection with link
  const replaced = await chrome.tabs.sendMessage(tab.id, { type: "qm_replace_selection_with_text", text: url })
    .catch(() => null);

  if (!replaced?.ok) return setStatus(replaced?.error || "Could not insert link", "err");

  setStatus("Inserted encrypted link ✅", "ok");
});

decryptBtn.addEventListener("click", async () => {
  setStatus("Decrypting...", "muted");
  plaintextEl.value = "";

  const link = linkInput.value.trim();
  if (!link) return setStatus("Paste a /m/<id> link", "err");

  const r = await send({ type: "qm_decrypt_link", link });
  if (!r?.ok) return setStatus(r?.error || "Decrypt failed", "err");

  plaintextEl.value = r.result.plaintext || "";
  setStatus(`Decrypted ✅ (key v${r.result.keyVersion})`, "ok");
});

load();
