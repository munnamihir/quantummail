// extension/content.js

let lastSelectionText = "";

document.addEventListener("selectionchange", () => {
  try {
    const t = (window.getSelection()?.toString() || "").trim();
    if (t) lastSelectionText = t;
  } catch {}
});

function getSelectionText() {
  const t = (window.getSelection()?.toString() || "").trim();
  if (t) return t;
  return (lastSelectionText || "").trim();
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "QM_GET_SELECTION") {
        sendResponse({ ok: true, text: getSelectionText() });
        return;
      }

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

        if (active && active.isContentEditable) {
          document.execCommand("insertText", false, link);
          sendResponse({ ok: true });
          return;
        }

        // Gmail fallback: try to find compose editor
        const editor = document.querySelector('[role="textbox"][contenteditable="true"]');
        if (editor) {
          editor.focus();
          document.execCommand("insertText", false, link);
          sendResponse({ ok: true });
          return;
        }

        sendResponse({
          ok: false,
          error: "Could not insert link. Click inside Gmail compose body and try again."
        });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();

  return true;
});

// -----------------------
// Decrypt bridge for /m/<id>
// Portal page sends window.postMessage -> content script -> background -> page
// -----------------------
function getMsgIdFromPath() {
  // /m/<id>
  const parts = location.pathname.split("/").filter(Boolean);
  if (parts[0] === "m" && parts[1]) return parts[1];
  return null;
}

if (location.pathname.startsWith("/m/")) {
  window.addEventListener("message", (event) => {
    const data = event.data || {};
    if (data?.source !== "quantummail-portal") return;
    if (data?.type !== "QM_DECRYPT_REQUEST") return;

    const msgId = data.msgId || getMsgIdFromPath();
    chrome.runtime.sendMessage({ type: "QM_DECRYPT_LINK", msgId }, (resp) => {
      const out = resp?.ok
        ? { source: "quantummail-extension", type: "QM_DECRYPT_RESULT", ok: true, plaintext: resp.plaintext }
        : { source: "quantummail-extension", type: "QM_DECRYPT_RESULT", ok: false, error: resp?.error || "Decrypt failed" };

      window.postMessage(out, "*");
    });
  });
}
