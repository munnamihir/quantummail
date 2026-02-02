import {
  normalizeBase,
  getSession,
  setSession,
  aesEncrypt,
  importPublicSpkiB64,
  rsaWrapDek
} from "./qm.js";

async function apiJson(serverBase, path, { method = "GET", token = "", body = null } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body) headers["Content-Type"] = "application/json";

  const res = await fetch(`${serverBase}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data;
}

function findUserByUsername(users, username) {
  const target = String(username || "").trim().toLowerCase();
  return (users || []).find(u => String(u.username || "").trim().toLowerCase() === target);
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === "QM_LOGIN") {
        const serverBase = normalizeBase(msg.serverBase);
        const orgId = String(msg.orgId || "").trim();
        const username = String(msg.username || "").trim();
        const password = String(msg.password || "");

        const data = await apiJson(serverBase, "/auth/login", {
          method: "POST",
          body: { orgId, username, password }
        });

        await setSession({
          serverBase,
          token: data.token,
          user: data.user
        });

        sendResponse({ ok: true });
        return;
      }

      if (msg?.type === "QM_ENCRYPT_SELECTION") {
        const s = await getSession();
        if (!s?.token) throw new Error("Not logged in");

        // Ask active tab for selection
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.id) throw new Error("No active tab");

        const sel = await new Promise((resolve) => {
          chrome.tabs.sendMessage(tab.id, { type: "QM_GET_SELECTION" }, (resp) => resolve(resp));
        });

        const selectedText = String(sel?.text || "").trim();
        if (!selectedText) throw new Error("Select text in the email body first.");

        const recipients = Array.isArray(msg.recipients) ? msg.recipients : [];
        if (!recipients.length) throw new Error("No recipients provided");

        // Fetch org users + pubkeys
        const orgUsers = await apiJson(s.serverBase, "/org/users", { token: s.token });
        const users = orgUsers.users || [];

        // Encrypt with AES-GCM (per message)
        const enc = await aesEncrypt(selectedText, "gmail");

        // Wrap DEK for each recipient AND sender
        const wrappedKeys = {};

        // sender must exist + have pubkey (so sender can decrypt later)
        const me = users.find(u => u.userId === s.user.userId) || findUserByUsername(users, s.user.username);
        if (!me) throw new Error("Sender user not found in org/users");
        if (!me.publicKeySpkiB64) throw new Error(`User "${s.user.username}" has no public key registered (login once).`);

        // recipients
        for (const rName of recipients) {
          const u = findUserByUsername(users, rName);
          if (!u) throw new Error(`User "${rName}" not found in org`);
          if (!u.publicKeySpkiB64) throw new Error(`User "${rName}" has no public key registered (they must login once).`);

          const pub = await importPublicSpkiB64(u.publicKeySpkiB64);
          wrappedKeys[u.userId] = await rsaWrapDek(pub, enc.rawDek);
        }

        // include sender
        {
          const pub = await importPublicSpkiB64(me.publicKeySpkiB64);
          wrappedKeys[me.userId] = await rsaWrapDek(pub, enc.rawDek);
        }

        // Store message on server (ciphertext + wrappedKeys)
        const saved = await apiJson(s.serverBase, "/api/messages", {
          method: "POST",
          token: s.token,
          body: {
            iv: enc.ivB64Url,
            ciphertext: enc.ctB64Url,
            aad: enc.aad,
            wrappedKeys
          }
        });

        const url = saved.url;
        if (!url) throw new Error("Server did not return url");

        // Insert link into Gmail editor
        const ins = await new Promise((resolve) => {
          chrome.tabs.sendMessage(tab.id, { type: "QM_INSERT_LINK", url }, (resp) => resolve(resp));
        });

        if (!ins?.ok) throw new Error(ins?.error || "Could not insert link");

        sendResponse({ ok: true, url });
        return;
      }

      // Decrypt flow is done by portal decrypt page posting window message to content script,
      // and content script calling background via QM_DECRYPT_LINK — you can add it later.
      sendResponse({ ok: false, error: "Unknown message type" });
    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();

  return true;
});
