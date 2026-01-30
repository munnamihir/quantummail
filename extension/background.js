import mlkem from './vendor/mlkem.js';

const te = new TextEncoder();
const td = new TextDecoder();

function abToB64(ab) {
  const bytes = new Uint8Array(ab);
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function b64ToAb(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

function randBytes(len) {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

async function deriveAesKeyFromPassphrase(passphrase, saltB, iterations = 200000) {
  const baseKey = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltB, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function aesGcmEncrypt(aesKey, plaintext) {
  const iv = randBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, te.encode(plaintext));
  return { iv, ct };
}

async function storeMessage(serverBase, payload) {
  const res = await fetch(`${serverBase.replace(/\/$/, '')}/api/messages`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    let msg = `Server error (${res.status})`;
    try {
      const j = await res.json();
      msg = j.error || msg;
    } catch {}
    throw new Error(msg);
  }
  return res.json();
}

async function encryptAndUpload({ plaintext, mode, recipientPkB64, passphrase, serverBase }) {
  if (!serverBase) serverBase = 'http://localhost:5173';
  let aesKey;
  let kemCiphertextB64;
  let saltB64;

  if (mode === 'pqc') {
    if (!recipientPkB64) throw new Error('Missing recipient public key');
    const recipientPk = await mlkem.importKey('raw-public', b64ToAb(recipientPkB64), { name: 'ML-KEM-768' }, true, ['encapsulateKey']);
    const enc = await mlkem.encapsulateKey(
      { name: 'ML-KEM-768' },
      recipientPk,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    aesKey = enc.sharedKey;
    kemCiphertextB64 = abToB64(enc.ciphertext);
  } else {
    if (!passphrase) throw new Error('Missing passphrase');
    const salt = randBytes(16);
    saltB64 = abToB64(salt.buffer);
    aesKey = await deriveAesKeyFromPassphrase(passphrase, salt, 200000);
  }

  const { iv, ct } = await aesGcmEncrypt(aesKey, plaintext);

  const payload = {
    mode,
    alg: 'AES-256-GCM',
    iv: abToB64(iv.buffer),
    ciphertext: abToB64(ct),
    ...(saltB64 ? { salt: saltB64, kdf: 'PBKDF2-SHA256', kdfIterations: '200000' } : {}),
    ...(kemCiphertextB64 ? { kem: { alg: 'ML-KEM-768', ciphertext: kemCiphertextB64 } } : {})
  };

  return storeMessage(serverBase, payload);
}

chrome.runtime.onInstalled.addListener(() => {
  console.log("QuantumMail service worker installed");
});

// optional: respond to content script messages
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === "PING") {
    sendResponse({ ok: true, from: "background" });
    return true;
  }

  if (msg?.type === "OPEN_PORTAL") {
    // Opens your portal (works for local dev)
    chrome.tabs.create({ url: "http://localhost:5173/portal/compose.html" });
    sendResponse({ ok: true });
    return true;
  }
});

