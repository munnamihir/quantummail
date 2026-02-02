const DEFAULTS = {
  serverBase: "http://localhost:5173",
  orgId: "org_demo"
};

function $(id) { return document.getElementById(id); }
function setMsg(t) { $("msg").textContent = t || ""; }
function setErr(t) { $("err").textContent = t || ""; }
function setOk(t) { $("ok").textContent = t || ""; }

function normalizeBase(url) {
  return String(url || "").replace(/\/+$/, "");
}

async function getSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(DEFAULTS, (v) => resolve(v || DEFAULTS));
  });
}

async function setSettings(patch) {
  return new Promise((resolve) => chrome.storage.sync.set(patch, resolve));
}

async function sendBg(msg) {
  return await chrome.runtime.sendMessage(msg);
}

(async () => {
  const s = await getSettings();
  $("serverBase").value = s.serverBase;
  $("orgId").value = s.orgId;

  $("btnLogin").addEventListener("click", async () => {
    try {
      setErr(""); setOk(""); setMsg("Logging in…");
      const serverBase = normalizeBase($("serverBase").value);
      const orgId = $("orgId").value.trim();
      const username = $("username").value.trim();
      const password = $("password").value;

      await setSettings({ serverBase, orgId });

      const r = await sendBg({ type: "QM_LOGIN", serverBase, orgId, username, password });
      if (!r?.ok) throw new Error(r?.error || "Login failed");
      setMsg("");
      setOk("Logged in ✅ Keys generated/registered if needed.");
    } catch (e) {
      setMsg("");
      setErr(String(e?.message || e));
    }
  });

  $("btnEncryptSelection").addEventListener("click", async () => {
    try {
      setErr(""); setOk(""); setMsg("Encrypting selection…");
      const recipients = $("recipients").value.trim();

      const r = await sendBg({ type: "QM_ENCRYPT_SELECTION", recipients });
      if (!r?.ok) throw new Error(r?.error || "Encrypt failed");
      setMsg("");
      setOk("Link copied/inserted ✅");
    } catch (e) {
      setMsg("");
      setErr(String(e?.message || e));
    }
  });
})();
