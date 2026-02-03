// portal/decrypt.js

const $ = (id) => document.getElementById(id);

function getMsgIdFromPath() {
  const parts = location.pathname.split("/").filter(Boolean);
  if (parts[0] === "m" && parts[1]) return parts[1];
  return "";
}

function ok(msg) { $("ok").textContent = msg || ""; }
function err(msg) { $("err").textContent = msg || ""; }

function setBusy(busy) {
  const btn = $("btnDecrypt");
  btn.disabled = !!busy;
  btn.textContent = busy ? "Decrypting…" : "Decrypt";
}

const msgId = getMsgIdFromPath();
$("msgId").textContent = msgId || "-";

// Auto-fill server base to current origin
$("serverBase").value = window.location.origin;
$("serverBase").readOnly = true;

function requestDecrypt() {
  ok(""); err("");
  $("out").value = "";

  if (!msgId) { err("No message id in URL."); return; }

  const serverBase = window.location.origin; // ✅ auto
  const orgId = ($("orgId").value || "").trim();
  const username = ($("username").value || "").trim();
  const password = ($("password").value || "");

  if (!orgId || !username || !password) {
    err("Please enter orgId, username, and password.");
    return;
  }

  setBusy(true);
  ok("Contacting extension…");

  window.postMessage(
    {
      source: "quantummail-portal",
      type: "QM_LOGIN_AND_DECRYPT_REQUEST",
      msgId,
      serverBase,
      orgId,
      username,
      password
    },
    "*"
  );

  const timeout = setTimeout(() => {
    setBusy(false);
    err(
      "QuantumMail extension not detected.\n" +
      "1) Install/enable the extension\n" +
      "2) Refresh this page\n" +
      "3) Try again"
    );
  }, 4000);

  window.__qmDecryptTimeout = timeout;
}

window.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data?.source !== "quantummail-extension") return;
  if (data?.type !== "QM_DECRYPT_RESULT") return;

  if (window.__qmDecryptTimeout) {
    clearTimeout(window.__qmDecryptTimeout);
    window.__qmDecryptTimeout = null;
  }

  setBusy(false);

  if (data.ok) {
    ok("Decrypted ✅ (access audited)");
    $("out").value = data.plaintext || "";
  } else {
    err(data.error || "Decrypt failed");
  }
});

$("btnDecrypt").addEventListener("click", requestDecrypt);

$("password")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") requestDecrypt();
});
