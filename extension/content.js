// QuantumMail Enterprise - Gmail content script (SAFE v3)
// Uses execCommand('insertText') to avoid Range recursion / stack overflow.

function findComposeEditor() {
  // Gmail compose editor is usually role=textbox + contenteditable
  const editors = Array.from(
    document.querySelectorAll('div[role="textbox"][contenteditable="true"]')
  );

  // Pick the most recently focused/visible editor
  for (let i = editors.length - 1; i >= 0; i--) {
    const el = editors[i];
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    const visible = r.width > 50 && r.height > 20 && s.display !== "none" && s.visibility !== "hidden";
    if (visible) return el;
  }
  return null;
}

function selectionInside(editor) {
  const sel = window.getSelection();
  if (!sel || sel.rangeCount === 0) return false;
  const range = sel.getRangeAt(0);

  // Check common ancestor container
  let node = range.commonAncestorContainer;
  if (node.nodeType === Node.TEXT_NODE) node = node.parentNode;

  return !!(node && editor.contains(node));
}

function getSelectedText() {
  const sel = window.getSelection();
  if (!sel || sel.rangeCount === 0) return "";
  return sel.toString() || "";
}

function replaceSelectionWithText(editor, text) {
  if (!selectionInside(editor)) {
    throw new Error("Highlight text inside the Gmail email body first.");
  }

  // Focus editor, then insert text at current selection.
  // execCommand avoids fragile Range operations.
  editor.focus();

  // Try execCommand first
  const ok = document.execCommand("insertText", false, text);
  if (ok) return;

  // Fallback: minimal Range replacement if execCommand fails
  const sel = window.getSelection();
  if (!sel || sel.rangeCount === 0) throw new Error("No selection");
  const range = sel.getRangeAt(0);
  range.deleteContents();
  range.insertNode(document.createTextNode(text));
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  try {
    if (msg?.type === "qm_get_selected_text") {
      const editor = findComposeEditor();
      if (!editor) {
        sendResponse({ ok: false, error: "Open Gmail compose and click inside the email body first." });
        return true;
      }

      const text = getSelectedText();
      if (!text.trim()) {
        sendResponse({ ok: false, error: "Select (highlight) text inside the email body first." });
        return true;
      }

      // If selection isn't in editor, show a clear error
      if (!selectionInside(editor)) {
        sendResponse({ ok: false, error: "Your selection is not inside the email body. Click the body and highlight text again." });
        return true;
      }

      sendResponse({ ok: true, text });
      return true;
    }

    if (msg?.type === "qm_replace_selection_with_text") {
      const editor = findComposeEditor();
      if (!editor) {
        sendResponse({ ok: false, error: "Could not find Gmail compose body." });
        return true;
      }

      const t = String(msg.text || "");
      if (!t) {
        sendResponse({ ok: false, error: "Empty replacement text" });
        return true;
      }

      replaceSelectionWithText(editor, t);
      sendResponse({ ok: true });
      return true;
    }

    sendResponse({ ok: false, error: "Unknown request" });
    return true;
  } catch (e) {
    sendResponse({ ok: false, error: String(e?.message || e) });
    return true;
  }
});
