// portal/decrypt.js

const $ = (id) => document.getElementById(id);

function getMsgIdFromPath() {
  const parts = location.pathname.split("/").filter(Boolean);
  if (parts[0] === "m" && parts[1]) return parts[1];
  return "";
}

function ok(msg) { $("ok").textContent = msg || ""; }
function err(msg) { $("err").textContent = msg || ""; }

const msgId = getMsgIdFromPath();
$("msgId").textContent = msgId || "-";

function setBusy(isBusy) {
  $("btnDecrypt").disabled = !!isBusy;
  $("btnDecrypt").textContent = isBusy ? "Decrypting…" : "Decrypt";
}

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

  // Send creds to extension (content script bridge)
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

  // If extension isn't installed, we’ll timeout with a helpful error.
  const t = setTimeout(() => {
    setBusy(false);
    err("QuantumMail extension not detected. Please install/enable the extension and refresh.");
  }, 4000);

  // We clear this timeout when result arrives
  window.__qmDecryptTimeout = t;
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

// Enter key submits
$("password").addEventListener("keydown", (e) => {
  if (e.key === "Enter") requestDecrypt();
});
