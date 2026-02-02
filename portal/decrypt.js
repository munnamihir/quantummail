// portal/decrypt.js
const $ = (id) => document.getElementById(id);

function getMsgIdFromPath() {
  // /m/<id>
  const parts = location.pathname.split("/").filter(Boolean);
  if (parts[0] === "m" && parts[1]) return parts[1];
  return "";
}

function ok(msg) { $("ok").textContent = msg || ""; }
function err(msg) { $("err").textContent = msg || ""; }

const msgId = getMsgIdFromPath();
$("msgId").textContent = msgId || "-";

function requestDecrypt() {
  ok(""); err("");
  $("out").value = "";

  if (!msgId) {
    err("No message id in URL.");
    return;
  }

  // Ask the extension (via content-script bridge)
  window.postMessage(
    { source: "quantummail-portal", type: "QM_DECRYPT_REQUEST", msgId, origin: window.location.origin },
    "*"
  );

  ok("Decrypt request sent… (make sure you are logged in in the extension)");
}

window.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data?.source !== "quantummail-extension") return;
  if (data?.type !== "QM_DECRYPT_RESULT") return;

  if (data.ok) {
    ok("Decrypted ✅");
    $("out").value = data.plaintext || "";
  } else {
    err(data.error || "Decrypt failed");
  }
});

$("btnDecrypt").addEventListener("click", requestDecrypt);
