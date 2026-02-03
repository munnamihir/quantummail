// extension/content.js
// Gmail-safe selection caching + REPLACE selection with link + decrypt bridge

let cachedSelectionText = "";
let cachedRange = null;

function cloneRangeIfPossible(sel) {
  try {
    if (!sel || sel.rangeCount === 0) return null;
    const r = sel.getRangeAt(0);
    // clone so it survives focus changes a bit better
    return r.cloneRange();
  } catch {
    return null;
  }
}

function cacheSelection() {
  try {
    const sel = window.getSelection?.();
    if (!sel) return;

    const text = String(sel.toString() || "").trim();
    if (text) cachedSelectionText = text;

    const range = cloneRangeIfPossible(sel);
    if (range) cachedRange = range;
  } catch {}
}

// Cache selection aggressively
document.addEventListener("mouseup", cacheSelection);
document.addEventListener("keyup", cacheSelection);
document.addEventListener("selectionchange", cacheSelection);

// Get best-available selection text
function getSelectionTextRobust() {
  try {
    const live = String(window.getSelection?.()?.toString() || "").trim();
    if (live) return live;
  } catch {}

  if (cachedSelectionText) return cachedSelectionText;
  return "";
}

function isLikelyGmailEditor(node) {
  if (!node) return false;
  if (node.nodeType === Node.ELEMENT_NODE) {
    const el = node;
    if (el.isContentEditable) return true;
    if (el.getAttribute?.("contenteditable") === "true") return true;
  }
  return false;
}

function replaceUsingExecCommand(link) {
  try {
    // Works when selection is still active
    document.execCommand("insertText", false, link);
    return true;
  } catch {
    return false;
  }
}

function replaceUsingCachedRange(link) {
  try {
    if (!cachedRange) return false;

    const range = cachedRange;

    // Ensure range is still connected to DOM
    const common = range.commonAncestorContainer;
    const containerEl = common.nodeType === Node.ELEMENT_NODE ? common : common.parentElement;

    if (!containerEl || !document.contains(containerEl)) return false;

    // Gmail editor often uses contenteditable divs — ensure we are inside something editable
    let cur = containerEl;
    let okEditable = false;
    while (cur && cur !== document.body) {
      if (cur.isContentEditable || cur.getAttribute?.("contenteditable") === "true") {
        okEditable = true;
        break;
      }
      cur = cur.parentElement;
    }
    if (!okEditable) return false;

    // Replace selected content
    range.deleteContents();
    range.insertNode(document.createTextNode(link));

    // Move caret to end of inserted link
    range.collapse(false);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);

    return true;
  } catch {
    return false;
  }
}

// If we can't replace selection, fallback: insert at compose cursor
function insertIntoComposeFallback(link) {
  const editor =
    document.activeElement?.isContentEditable
      ? document.activeElement
      : document.querySelector('[role="textbox"][contenteditable="true"]') ||
        document.querySelector('div[aria-label][contenteditable="true"]');

  if (editor) {
    editor.focus();
    document.execCommand("insertText", false, link);
    return true;
  }
  return false;
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "QM_GET_SELECTION") {
        const text = getSelectionTextRobust();
        sendResponse({ ok: true, text });
        return;
      }

      // ✅ Replace currently selected text with link
      if (msg?.type === "QM_REPLACE_SELECTION_WITH_LINK") {
        const url = String(msg.url || "").trim();
        if (!url) {
          sendResponse({ ok: false, error: "Missing url" });
          return;
        }

        // 1) Try direct replace with current selection
        const directOk = replaceUsingExecCommand(url);
        if (directOk) {
          // clear cache to avoid accidental reuse
          cachedSelectionText = "";
          cachedRange = null;
          sendResponse({ ok: true });
          return;
        }

        // 2) Try cached range (handles popup stealing focus)
        const cachedOk = replaceUsingCachedRange(url);
        if (cachedOk) {
          cachedSelectionText = "";
          cachedRange = null;
          sendResponse({ ok: true });
          return;
        }

        // 3) Fallback insert (not perfect, but better than nothing)
        const fallbackOk = insertIntoComposeFallback(url);
        if (!fallbackOk) {
          sendResponse({
            ok: false,
            error: "Could not replace selection. Re-select text in the compose body and try again."
          });
          return;
        }

        sendResponse({ ok: true, warning: "Inserted link, but could not delete original selection." });
        return;
      }

      sendResponse({ ok: false, error: "Unknown message" });
    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();

  return true;
});

// -----------------------
// Decrypt bridge for /m/<id>
// -----------------------
function getMsgIdFromPath() {
  const parts = location.pathname.split("/").filter(Boolean);
  if (parts[0] === "m" && parts[1]) return parts[1];
  return null;
}

if (location.pathname.startsWith("/m/")) {
  window.addEventListener("message", (event) => {
    const data = event.data || {};
    if (data?.source !== "quantummail-portal") return;
    if (data?.type !== "QM_LOGIN_AND_DECRYPT_REQUEST") return;

    const msgId = data.msgId || getMsgIdFromPath();

    chrome.runtime.sendMessage(
      {
        type: "QM_LOGIN_AND_DECRYPT",
        msgId,
        serverBase: data.serverBase,
        orgId: data.orgId,
        username: data.username,
        password: data.password
      },
      (resp) => {
        const out = resp?.ok
          ? { source: "quantummail-extension", type: "QM_DECRYPT_RESULT", ok: true, plaintext: resp.plaintext }
          : { source: "quantummail-extension", type: "QM_DECRYPT_RESULT", ok: false, error: resp?.error || "Decrypt failed" };

        window.postMessage(out, "*");
      }
    );
  });
}
