// content.js
// QuantumMail: supports encrypt/decrypt for BOTH compose mode (contenteditable editor)
// and read mode (opened email). It can:
//  - GET_SELECTION: return selected text anywhere on the page
//  - REPLACE_SELECTION: replace selection in compose editor if present, otherwise replace selection in read mode
//
// Works on Gmail + Outlook (web). Designed for MV3 dynamic injection.

(() => {
  const EXT = "QuantumMail";
  const log = (...args) => console.log(`[${EXT}]`, ...args);

  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

  // ---------- Site checks ----------
  function isGmail() {
    return location.hostname === "mail.google.com";
  }
  function isOutlook() {
    return (
      location.hostname === "outlook.office.com" ||
      location.hostname === "outlook.live.com"
    );
  }

  // ---------- Compose editor detection ----------
  function findGmailEditor() {
    return (
      document.querySelector('div[role="textbox"][aria-label="Message Body"]') ||
      document.querySelector('div[role="dialog"] div[role="textbox"][contenteditable="true"]') ||
      null
    );
  }

  function findOutlookEditor() {
    // Outlook editor is usually contenteditable with role="textbox"
    const candidates = Array.from(
      document.querySelectorAll('div[contenteditable="true"][role="textbox"]')
    ).filter((el) => {
      const r = el.getBoundingClientRect();
      return r.width > 50 && r.height > 50;
    });

    if (candidates.length) return candidates[0];

    // Fallback: any visible contenteditable
    const fallback = Array.from(
      document.querySelectorAll('div[contenteditable="true"]')
    ).filter((el) => {
      const r = el.getBoundingClientRect();
      return r.width > 50 && r.height > 50;
    });

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

  // ---------- Selection helpers ----------
  function getSelectedText() {
    const sel = window.getSelection?.();
    return String(sel ? sel.toString() : "");
  }

  // Replace selection *inside compose editor* (contenteditable).
  // If the selection is not inside the editor, caret is moved to the end and text is inserted there.
  function replaceSelectionInEditor(editorEl, replacementText) {
    try {
      editorEl.focus();

      const sel = window.getSelection?.();
      if (!sel) return { ok: false, error: "Selection API not available" };

      // If selection isn't inside editor, move caret to end
      if (
        sel.rangeCount === 0 ||
        !editorEl.contains(sel.getRangeAt(0).commonAncestorContainer)
      ) {
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

      // Move caret after inserted node
      range.setStartAfter(node);
      range.setEndAfter(node);
      sel.removeAllRanges();
      sel.addRange(range);

      // Notify SPA editor
      editorEl.dispatchEvent(new InputEvent("input", { bubbles: true }));
      return { ok: true, mode: "compose" };
    } catch (e) {
      return { ok: false, error: String(e?.message || e) };
    }
  }

  // Replace selection anywhere on page (read mode).
  // This does NOT require a compose editor; it just replaces the DOM selection with text.
  function replaceSelectionAnywhere(replacementText) {
    try {
      const sel = window.getSelection?.();
      if (!sel || sel.rangeCount === 0) {
        return { ok: false, error: "No selection found. Highlight the token/text first." };
      }

      const range = sel.getRangeAt(0);
      range.deleteContents();

      const node = document.createTextNode(String(replacementText ?? ""));
      range.insertNode(node);

      // Move caret after inserted node
      range.setStartAfter(node);
      range.setEndAfter(node);
      sel.removeAllRanges();
      sel.addRange(range);

      return { ok: true, mode: "read" };
    } catch (e) {
      return { ok: false, error: String(e?.message || e) };
    }
  }

  // ---------- Message API ----------
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    (async () => {
      try {
        if (!msg || typeof msg !== "object") {
          sendResponse({ ok: false, error: "Invalid message" });
          return;
        }

        if (msg.type === "GET_SELECTION") {
          sendResponse({ ok: true, selectedText: getSelectedText() });
          return;
        }

        if (msg.type === "REPLACE_SELECTION") {
          const text = String(msg.text ?? "");

          // First try compose editor (short wait)
          const editor = await waitForEditor(1500);
          if (editor) {
            sendResponse(replaceSelectionInEditor(editor, text));
            return;
          }

          // Fallback: replace selection in read mode
          sendResponse(replaceSelectionAnywhere(text));
          return;
        }

        if (msg.type === "PING") {
          sendResponse({
            ok: true,
            from: "content",
            href: location.href,
            host: location.hostname
          });
          return;
        }

        sendResponse({ ok: false, error: `Unknown message type: ${msg.type}` });
      } catch (e) {
        sendResponse({ ok: false, error: String(e?.message || e) });
      }
    })();

    return true; // async sendResponse
  });

  log("content script loaded", location.href);
})();
