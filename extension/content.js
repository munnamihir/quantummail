// content.js
// QuantumMail MVP content script: get selection + replace selection in compose editor.

(() => {
  const EXT = "QuantumMail";
  const log = (...args) => console.log(`[${EXT}]`, ...args);

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function isGmail() {
    return location.hostname === "mail.google.com";
  }

  function isOutlook() {
    return (
      location.hostname === "outlook.office.com" ||
      location.hostname === "outlook.live.com"
    );
  }

  // Find compose editor (best effort)
  function findGmailEditor() {
    return (
      document.querySelector('div[role="textbox"][aria-label="Message Body"]') ||
      document.querySelector('div[role="dialog"] div[role="textbox"][contenteditable="true"]') ||
      null
    );
  }

  function findOutlookEditor() {
    const candidates = Array.from(
      document.querySelectorAll('div[contenteditable="true"][role="textbox"]')
    ).filter((el) => {
      const r = el.getBoundingClientRect();
      return r.width > 50 && r.height > 50;
    });

    if (candidates.length) return candidates[0];

    const fallback = Array.from(document.querySelectorAll('div[contenteditable="true"]')).filter(
      (el) => {
        const r = el.getBoundingClientRect();
        return r.width > 50 && r.height > 50;
      }
    );

    return fallback[0] || null;
  }

  function findEditor() {
    if (isGmail()) return findGmailEditor();
    if (isOutlook()) return findOutlookEditor();
    return null;
  }

  async function waitForEditor(timeoutMs = 15000) {
    const start = Date.now();
    let editor = findEditor();
    while (!editor && Date.now() - start < timeoutMs) {
      await sleep(250);
      editor = findEditor();
    }
    return editor;
  }

  function getSelectedText() {
    const sel = window.getSelection?.();
    const txt = sel ? sel.toString() : "";
    return String(txt || "");
  }

  function replaceSelectionInEditor(editorEl, replacementText) {
    editorEl.focus();

    const sel = window.getSelection?.();
    if (!sel) return { ok: false, error: "No selection API available" };

    // If selection isn't inside editor, move caret to end (and insert)
    if (sel.rangeCount === 0 || !editorEl.contains(sel.getRangeAt(0).commonAncestorContainer)) {
      const endRange = document.createRange();
      endRange.selectNodeContents(editorEl);
      endRange.collapse(false);
      sel.removeAllRanges();
      sel.addRange(endRange);
    }

    // Replace current selection
    const range = sel.getRangeAt(0);
    range.deleteContents();

    const node = document.createTextNode(String(replacementText ?? ""));
    range.insertNode(node);

    // Move caret after inserted node
    range.setStartAfter(node);
    range.setEndAfter(node);
    sel.removeAllRanges();
    sel.addRange(range);

    // Notify SPA editor
    editorEl.dispatchEvent(new InputEvent("input", { bubbles: true }));
    return { ok: true };
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    (async () => {
      try {
        if (!msg || typeof msg !== "object") {
          sendResponse({ ok: false, error: "Invalid message" });
          return;
        }

        if (msg.type === "PING") {
          sendResponse({ ok: true, from: "content", url: location.href });
          return;
        }

        if (msg.type === "GET_SELECTION") {
          sendResponse({ ok: true, selectedText: getSelectedText() });
          return;
        }

        if (msg.type === "REPLACE_SELECTION") {
          const text = String(msg.text ?? "");
          const editor = await waitForEditor(15000);
          if (!editor) {
            sendResponse({
              ok: false,
              error: "Compose editor not found. Click Compose first, then select text inside it.",
            });
            return;
          }

          const res = replaceSelectionInEditor(editor, text);
          sendResponse(res);
          return;
        }

        sendResponse({ ok: false, error: `Unknown message type: ${msg.type}` });
      } catch (e) {
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
    })();

    return true;
  });

  log("content script loaded", location.href);
})();
