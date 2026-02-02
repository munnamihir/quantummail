function setStatus(msg) {
  const el = document.getElementById("status");
  if (el) el.textContent = msg;
}
function setError(msg) {
  const el = document.getElementById("err");
  if (el) el.textContent = msg || "";
}
function setPlaintext(msg) {
  const el = document.getElementById("plaintext");
  if (el) el.textContent = msg || "";
}

function getMsgId() {
  const parts = location.pathname.split("/").filter(Boolean);
  const i = parts.indexOf("m");
  if (i >= 0 && parts[i + 1]) return parts[i + 1];
  return parts[parts.length - 1] || "";
}

const msgId = getMsgId();

function requestDecrypt() {
  setError("");
  setStatus("Requesting decrypt from extension…");

  // Page -> content script -> background
  window.postMessage(
    {
      source: "quantummail-portal",
      type: "QM_DECRYPT_REQUEST",
      msgId,
      origin: location.origin
    },
    "*"
  );
}

window.addEventListener("message", (event) => {
  const data = event.data || {};
  if (data?.source !== "quantummail-extension") return;

  if (data.type === "QM_DECRYPT_RESULT") {
    if (data.ok) {
      setStatus("Decrypted ✅");
      setPlaintext(data.plaintext || "");
    } else {
      setStatus("Failed");
      setError(data.error || "Decrypt failed");
    }
  }
});

document.getElementById("btnDecrypt")?.addEventListener("click", requestDecrypt);

// Helpful message if extension not installed
setTimeout(() => {
  setStatus("If nothing happens, make sure the QuantumMail extension is installed and enabled.");
}, 800);
