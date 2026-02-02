// content.js
// QuantumMail: selection + replace selection in BOTH compose mode and read mode (opened email)

(() => {
  const EXT = "QuantumMail";
  const log = (...args) => console.log(`[${EXT}]`, ...args);

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  function isGmail() { return location.hostname === "mail.google.com"; }
  function isOutlook() { return location.hostname === "outlook.office.com" || location.hostname === "outlook.live.com"; }

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

  async function waitForEditor(timeoutMs = 1500) {
    const start = Date.now();
    let editor = findEditor();
    while (!editor && Date.now() - start < timeoutMs) {
      await sleep(200);
      editor = findEditor();
    }
    return editor;
  }

  function getSelectedText() {
    const sel = window.getSelection?.();
    return String(sel ? sel.toString() : "");
  }

  function replaceSelectionInEditor(editorEl, replacementText) {
    editorEl.focus();
    const sel = window.getSelection?.();
    if (!sel) return { ok: false, error: "Selection API not available" };

    if (sel.rangeCount === 0 || !editorEl.contains(sel.getRangeAt(0).commonAncestorContainer)) {
      const endRange = document.createRange();
      endRange.selectNodeContents(editorEl);
      endRange.collapse(false);
      sel.removeAllRanges();
      sel.addRange(endRange);
    }

    const range = sel.getRangeAt(0);
    range.deleteContents();

    const node = document.createTextNode(String(replacementText ?? ""));
    range.insertNode(node);

    range.setStartAfter(node);
    range.setEndAfter(node);
    sel.removeAllRanges();
    sel.addRange(range);

    editorEl.dispatchEvent(new InputEvent("input", { bubbles: true }));
    return { ok: true, mode: "compose" };
  }

  function replaceSelectionAnywhere(replacementText) {
    const sel = window.getSelection?.();
    if (!sel || sel.rangeCount === 0) return { ok: false, error: "No selection found. Highlight text first." };

    const range = sel.getRangeAt(0);
    range.deleteContents();

    const node = document.createTextNode(String(replacementText ?? ""));
    range.insertNode(node);

    range.setStartAfter(node);
    range.setEndAfter(node);
    sel.removeAllRanges();
    sel.addRange(range);

    return { ok: true, mode: "read" };
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    (async () => {
      try {
        if (!msg || typeof msg !== "object") return sendResponse({ ok: false, error: "Invalid message" });

        if (msg.type === "GET_SELECTION") {
          return sendResponse({ ok: true, selectedText: getSelectedText() });
        }

        if (msg.type === "REPLACE_SELECTION") {
          const text = String(msg.text ?? "");

          // Prefer compose editor if present, else replace in read view
          const editor = await waitForEditor(1500);
          if (editor) return sendResponse(replaceSelectionInEditor(editor, text));
          return sendResponse(replaceSelectionAnywhere(text));
        }

        return sendResponse({ ok: false, error: `Unknown message type: ${msg.type}` });
      } catch (e) {
        return sendResponse({ ok: false, error: String(e?.message || e) });
      }
    })();
    return true;
  });

  log("content script loaded", location.href);
})();
