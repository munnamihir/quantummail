import mlkem from '/portal/vendor/mlkem.js';
import {
  el, setStatus,
  abToB64, b64ToAb,
  deriveAesKeyFromPassphrase,
  aesGcmDecrypt
} from '/portal/util.js';

const metaEl = el('meta');
const statusEl = el('status');
const plaintextEl = el('plaintext');
const passphraseBox = document.getElementById('passphraseBox');
const pqcBox = document.getElementById('pqcBox');
const passphraseEl = el('passphrase');
const seedEl = el('seed');

function getIdFromPath() {
  const parts = location.pathname.split('/').filter(Boolean);
  const idx = parts.indexOf('m');
  if (idx !== -1 && parts[idx + 1]) return parts[idx + 1];
  // fallback if route is directly /m/<id>
  if (parts[0] === 'm' && parts[1]) return parts[1];
  return null;
}

async function fetchMsg(id) {
  const res = await fetch(`/api/messages/${id}`);
  if (!res.ok) throw new Error('Message not found');
  return res.json();
}

let msg;
let id;
(async () => {
  try {
    id = getIdFromPath();
    if (!id) throw new Error('Missing message id');
    msg = await fetchMsg(id);

    metaEl.textContent = `Message ${id} • mode=${msg.mode} • createdAt=${msg.createdAt || '—'}`;

    if (msg.mode === 'passphrase') {
      passphraseBox.style.display = '';
      pqcBox.style.display = 'none';
    } else {
      passphraseBox.style.display = 'none';
      pqcBox.style.display = '';
    }

    setStatus(statusEl, '');
  } catch (err) {
    console.error(err);
    metaEl.textContent = 'Could not load message.';
    setStatus(statusEl, err.message || 'Error', true);
  }
})();

el('decryptBtn').addEventListener('click', async () => {
  try {
    if (!msg) throw new Error('Message not loaded');
    setStatus(statusEl, 'Decrypting…');

    const iv = new Uint8Array(b64ToAb(msg.iv));
    const ct = b64ToAb(msg.ciphertext);

    let aesKey;

    if (msg.mode === 'passphrase') {
      const pw = (passphraseEl.value || '').trim();
      if (!pw) throw new Error('Enter a passphrase');
      if (!msg.salt) throw new Error('Missing salt');
      const salt = new Uint8Array(b64ToAb(msg.salt));
      const iters = msg.kdfIterations ? Number(msg.kdfIterations) : 200000;
      aesKey = await deriveAesKeyFromPassphrase(pw, salt, iters);
    } else {
      const seedB64 = (seedEl.value || '').trim();
      if (!seedB64) throw new Error('Paste your private key seed (base64)');
      if (!msg.kem?.ciphertext) throw new Error('Missing KEM ciphertext');

      const priv = await mlkem.importKey(
        'raw-seed',
        b64ToAb(seedB64),
        { name: 'ML-KEM-768' },
        false,
        ['decapsulateKey']
      );

      aesKey = await mlkem.decapsulateKey(
        { name: 'ML-KEM-768' },
        priv,
        b64ToAb(msg.kem.ciphertext),
        { name: 'AES-GCM', length: 256 },
        true,
        ['decrypt']
      );
    }

    const pt = await aesGcmDecrypt(aesKey, iv, ct);
    plaintextEl.textContent = pt;
    setStatus(statusEl, 'Done.');
  } catch (err) {
    console.error(err);
    setStatus(statusEl, err.message || 'Decrypt failed', true);
  }
});
