// content.js
// 1) Gmail: provide selected text
// 2) Portal decrypt page: relay window.postMessage requests to background

function isGmail() {
  return location.host === "mail.google.com";
}

function isPortalDecryptPage() {
  // Works for /m/<id> on localhost or *.app.github.dev
  return location.pathname.startsWith("/m/");
}

// -------------------- Gmail: selection helper --------------------
function getSelectionText() {
  const sel = window.getSelection();
  const text = sel ? sel.toString() : "";
  return (text || "").trim();
}

// Listen for background requests
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "QM_GET_SELECTION") {
        const text = getSelectionText();
        sendResponse({ ok: true, text });
        return;
      }

      // Optional: insert link into active element (Gmail editor)
      if (msg?.type === "QM_INSERT_LINK") {
        const link = msg.url;
        const active = document.activeElement;

        if (active && (active.tagName === "TEXTAREA" || active.tagName === "INPUT")) {
          const start = active.selectionStart ?? active.value.length;
          const end = active.selectionEnd ?? active.value.length;
          active.value = active.value.slice(0, start) + link + active.value.slice(end);
          sendResponse({ ok: true });
          return;
        }

        // Contenteditable (Gmail compose)
        if (active && active.isContentEditable) {
          document.execCommand("insertText", false, link);
          sendResponse({ ok: true });
          return;
        }

        sendResponse({ ok: false, error: "Could not insert link (click into Gmail editor first)" });
        return;
      }

      sendResponse({ ok: false, error: "Unknown message" });
    } catch (e) {
      sendResponse({ ok: false, error: String(e?.message || e) });
    }
  })();

  return true;
});

// -------------------- Portal decrypt relay --------------------
if (isPortalDecryptPage()) {
  window.addEventListener("message", (event) => {
    const data = event.data || {};
    if (data?.source !== "quantummail-portal") return;
    if (data.type !== "QM_DECRYPT_REQUEST") return;

    chrome.runtime.sendMessage(
      { type: "QM_DECRYPT_LINK", msgId: data.msgId, origin: data.origin },
      (resp) => {
        const out = resp?.ok
          ? { source: "quantummail-extension", type: "QM_DECRYPT_RESULT", ok: true, plaintext: resp.plaintext }
          : { source: "quantummail-extension", type: "QM_DECRYPT_RESULT", ok: false, error: resp?.error || "Decrypt failed" };

        window.postMessage(out, "*");
      }
    );
  });
}
