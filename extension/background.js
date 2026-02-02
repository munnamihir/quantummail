// extension/background.js
import {
  normalizeBase,
  getSession,
  setSession,
  aesEncrypt,
  aesDecrypt,
  importPublicSpkiB64,
  rsaWrapDek,
  b64UrlToBytes,
  getOrCreateRsaKeypair
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
  return (users || []).find((u) => String(u.username || "").trim().toLowerCase() === target);
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      // -----------------------
      // LOGIN
      // -----------------------
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

      // -----------------------
      // ENCRYPT SELECTED TEXT
      // -----------------------
      if (msg?.type === "QM_ENCRYPT_SELECTION") {
        const s = await getSession();
        if (!s?.token) throw new Error("Not logged in");

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

        const me =
          users.find((u) => u.userId === s.user.userId) || findUserByUsername(users, s.user.username);
        if (!me) throw new Error("Sender not found in org/users");
        if (!me.publicKeySpkiB64)
          throw new Error(`User "${s.user.username}" has no public key registered (login once).`);

        // recipients
        for (const rName of recipients) {
          const u = findUserByUsername(users, rName);
          if (!u) throw new Error(`User "${rName}" not found in org`);
          if (!u.publicKeySpkiB64)
            throw new Error(`User "${rName}" has no public key registered (they must login once).`);

          const pub = await importPublicSpkiB64(u.publicKeySpkiB64);
          wrappedKeys[u.userId] = await rsaWrapDek(pub, enc.rawDek);
        }

        // include sender
        {
          const pub = await importPublicSpkiB64(me.publicKeySpkiB64);
          wrappedKeys[me.userId] = await rsaWrapDek(pub, enc.rawDek);
        }

        // Store message on server
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

        const ins = await new Promise((resolve) => {
          chrome.tabs.sendMessage(tab.id, { type: "QM_INSERT_LINK", url }, (resp) => resolve(resp));
        });

        if (!ins?.ok) throw new Error(ins?.error || "Could not insert link");

        sendResponse({ ok: true, url });
        return;
      }

      // -----------------------
      // DECRYPT LINK (/m/<id>)
      // -----------------------
      if (msg?.type === "QM_DECRYPT_LINK") {
        const s = await getSession();
        if (!s?.token) throw new Error("Not logged in to decrypt (open extension and login).");

        const msgId = String(msg.msgId || "").trim();
        if (!msgId) throw new Error("Missing message id");

        // fetch message payload (server returns wrappedDek for this user only)
        const payload = await apiJson(s.serverBase, `/api/messages/${encodeURIComponent(msgId)}`, {
          token: s.token
        });

        const { iv, ciphertext, aad, wrappedDek } = payload || {};
        if (!iv || !ciphertext || !wrappedDek) throw new Error("Message not loaded (missing fields)");

        // unwrap DEK with RSA private key
        const { privateKey } = await getOrCreateRsaKeypair();
        const wrappedBytes = b64UrlToBytes(wrappedDek);

        let rawDekBytes;
        try {
          const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, wrappedBytes);
          rawDekBytes = new Uint8Array(raw);
        } catch {
          throw new Error("Failed to unwrap key. Are you logged in as the intended recipient?");
        }

        // AES-GCM decrypt
        const plaintext = await aesDecrypt(iv, ciphertext, aad || "gmail", rawDekBytes);

        sendResponse({ ok: true, plaintext });
        return;
      }

      sendResponse({ ok: false, error: "Unknown message type" });
    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();

  return true;
});
