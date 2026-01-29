export const te = new TextEncoder();
export const td = new TextDecoder();

export function abToB64(ab) {
  const bytes = new Uint8Array(ab);
  let bin = '';
  // Chunk to avoid call stack limits
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

export function b64ToAb(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

export function randBytes(len) {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

export async function deriveAesKeyFromPassphrase(passphrase, saltB, iterations = 200000) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    te.encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltB,
      iterations,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function aesGcmEncrypt(aesKey, plaintext) {
  const iv = randBytes(12);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    te.encode(plaintext)
  );
  return { iv, ct };
}

export async function aesGcmDecrypt(aesKey, ivB, ctB) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: ivB },
    aesKey,
    ctB
  );
  return td.decode(pt);
}

export async function copyToClipboard(text) {
  await navigator.clipboard.writeText(text);
}

export function el(id) {
  const e = document.getElementById(id);
  if (!e) throw new Error(`Missing element #${id}`);
  return e;
}

export function setStatus(targetEl, msg, isError = false) {
  targetEl.textContent = msg;
  targetEl.className = isError ? 'error' : '';
}
