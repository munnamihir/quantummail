const statusEl = document.getElementById("status");
const passEl = document.getElementById("pass");

function setStatus(msg) {
  statusEl.textContent = msg || "";
}

async function run(mode) {
  const passphrase = (passEl.value || "").trim();
  if (!passphrase) {
    setStatus("Enter a passphrase first.");
    return;
  }

  setStatus("Working...");

  const res = await chrome.runtime.sendMessage({
    type: "RUN_SELECTION",
    mode, // "encrypt" | "decrypt"
    passphrase
  });

  if (!res?.ok) {
    setStatus(`Error: ${res?.error || "Unknown error"}`);
    return;
  }

  setStatus(res.message || "Done.");
}

document.getElementById("encryptBtn").addEventListener("click", () => run("encrypt"));
document.getElementById("decryptBtn").addEventListener("click", () => run("decrypt"));

setStatus("");
