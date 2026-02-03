// extension/content.js (Gmail-safe selection caching + insert link + decrypt bridge)

let cachedSelectionText = "";
let lastActiveCompose = null;

// Track focus to remember the compose editor
document.addEventListener("focusin", (e) => {
  const el = e.target;
  if (!el) return;

  // Gmail compose body is usually contenteditable + role="textbox"
  if (el.isContentEditable || el.getAttribute?.("contenteditable") === "true") {
    const role = el.getAttribute?.("role");
    if (role === "textbox" || role === "combobox" || role === "document" || role === "main" || role === "presentation") {
      lastActiveCompose = el;
    } else {
      // Still keep it if editable; Gmail can be inconsistent
      lastActiveCompose = el;
    }
  }
});

// Cache selection aggressively (mouse up + key up + selectionchange)
function tryCacheSelection() {
  try {
    const sel = window.getSelection?.();
    if (!sel) return;

    // If something is selected
    const text = String(sel.toString() || "").trim();
    if (text) {
      cachedSelectionText = text;
      return;
    }

    // If no selection text, keep previous cache
  } catch {}
}

document.addEventListener("mouseup", tryCacheSelection);
document.addEventListener("keyup", tryCacheSelection);
document.addEventListener("selectionchange", tryCacheSelection);

// Gmail fallback: attempt to read selected range in compose editor
function getSelectionFromComposeFallback() {
  try {
    const sel = window.getSelection?.();
    if (!sel || sel.rangeCount === 0) return "";

    const range = sel.getRangeAt(0);
    const text = String(range.toString() || "").trim();
    if (text) return text;

    // If selection is collapsed, try using cached
    return "";
  } catch {
    return "";
  }
}

function getSelectionTextRobust() {
  // 1) Current live selection
  try {
    const live = String(window.getSelection?.()?.toString() || "").trim();
    if (live) return live;
  } catch {}

  // 2) Fallback via range
  const ranged = getSelectionFromComposeFallback();
  if (ranged) return ranged;

  // 3) Cached selection
  if (cachedSelectionText) return cachedSelectionText;

  return "";
}

// Insert link into Gmail editor reliably
function insertIntoCompose(link) {
  // Prefer current focused editable
  const active = document.activeElement;

  // Input/textarea
  if (active && (active.tagName === "TEXTAREA" || active.tagName === "INPUT")) {
    const start = active.selectionStart ?? active.value.length;
    const end = active.selectionEnd ?? active.value.length;
    active.value = active.value.slice(0, start) + link + active.value.slice(end);
    return true;
  }

  // Contenteditable focused
  if (active && active.isContentEditable) {
    active.focus();
    document.execCommand("insertText", false, link);
    return true;
  }

  // Gmail compose fallback: role textbox editable
  const editor =
    lastActiveCompose ||
    document.querySelector('[role="textbox"][contenteditable="true"]') ||
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

      if (msg?.type === "QM_INSERT_LINK") {
        const url = msg.url;
        if (!url) {
          sendResponse({ ok: false, error: "Missing url" });
          return;
        }

        const ok = insertIntoCompose(url);
        if (!ok) {
          sendResponse({
            ok: false,
            error: "Could not insert link. Click inside Gmail compose body and try again."
          });
          return;
        }

        sendResponse({ ok: true });
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
// Portal page sends window.postMessage -> content script -> background -> page
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
