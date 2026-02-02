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

        // Gmail compose is contenteditable but sometimes activeElement isn't inside it.
        // Fallback: try to find the compose body (best effort)
        const editor = document.querySelector('[role="textbox"][contenteditable="true"]');
        if (editor) {
          editor.focus();
          document.execCommand("insertText", false, link);
          sendResponse({ ok: true });
          return;
        }

        sendResponse({ ok: false, error: "Could not insert link. Click inside the Gmail compose body and try again." });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();

  return true;
});
