(() => {
  const ID_BTN = 'qm-fab';
  const ID_MODAL = 'qm-modal';

  if (document.getElementById(ID_BTN)) return;

  const style = document.createElement('style');
  style.textContent = `
    #${ID_BTN} {
      position: fixed; bottom: 18px; right: 18px; z-index: 2147483647;
      background: rgba(17,26,51,0.92);
      border: 1px solid rgba(255,255,255,0.18);
      color: #e8eefc; padding: 10px 12px;
      border-radius: 999px;
      font: 600 13px ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      box-shadow: 0 12px 28px rgba(0,0,0,0.35);
      cursor: pointer;
      user-select: none;
    }
    #${ID_BTN}:hover { filter: brightness(1.08); }

    #${ID_MODAL} {
      position: fixed; inset: 0; z-index: 2147483647;
      display: none;
      background: rgba(0,0,0,0.55);
      backdrop-filter: blur(6px);
    }
    #${ID_MODAL} .panel {
      position: absolute; right: 18px; bottom: 70px;
      width: min(520px, calc(100vw - 36px));
      background: linear-gradient(180deg, rgba(17,26,51,0.98) 0%, rgba(15,23,48,0.98) 100%);
      border: 1px solid rgba(255,255,255,0.16);
      border-radius: 16px;
      padding: 14px;
      color: #e8eefc;
      box-shadow: 0 20px 50px rgba(0,0,0,0.5);
      font: 13px ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
    }
    #${ID_MODAL} h3 { margin: 0 0 8px; font-size: 14px; }
    #${ID_MODAL} label { display:block; color: rgba(232,238,252,0.75); margin: 10px 0 6px; font-size: 12px; }
    #${ID_MODAL} textarea, #${ID_MODAL} input {
      width: 100%;
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.14);
      background: rgba(0,0,0,0.22);
      color: #e8eefc;
      padding: 10px;
      outline: none;
    }
    #${ID_MODAL} textarea { min-height: 140px; resize: vertical; }
    #${ID_MODAL} .row { display:flex; gap: 10px; align-items:center; }
    #${ID_MODAL} .row > * { flex: 1; }
    #${ID_MODAL} .btn {
      cursor: pointer;
      border: 1px solid rgba(77, 227, 193, 0.35);
      background: linear-gradient(180deg, rgba(77, 227, 193, 0.22) 0%, rgba(77, 227, 193, 0.08) 100%);
      color: #e8eefc;
      border-radius: 12px;
      padding: 9px 12px;
      font-weight: 700;
    }
    #${ID_MODAL} .btn.secondary { border-color: rgba(255,255,255,0.16); background: rgba(255,255,255,0.07); }
    #${ID_MODAL} .out {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 12px;
      background: rgba(0,0,0,0.26);
      border: 1px solid rgba(255,255,255,0.14);
      border-radius: 12px;
      padding: 10px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
    }
    #${ID_MODAL} .muted { color: rgba(232,238,252,0.7); font-size: 12px; }
    #${ID_MODAL} .error { color: #ff5c7a; font-weight: 700; }
  `;
  document.documentElement.appendChild(style);

  const btn = document.createElement('div');
  btn.id = ID_BTN;
  btn.textContent = 'QuantumMail';

  const modal = document.createElement('div');
  modal.id = ID_MODAL;
  modal.innerHTML = `
    <div class="panel" role="dialog" aria-modal="true">
      <div class="row" style="align-items:flex-start; gap: 12px">
        <div style="flex:1">
          <h3>Encrypt → get a link</h3>
          <div class="muted">Paste the link into your email.</div>
        </div>
        <button class="btn secondary" id="qm-close" style="flex:0 0 auto">Close</button>
      </div>

      <label>Server base URL</label>
      <input id="qm-server" placeholder="http://localhost:5173" />

      <label>Message</label>
      <textarea id="qm-message" placeholder="Paste email body here..."></textarea>

      <label>Mode</label>
      <div class="row" style="gap: 12px; align-items:flex-start">
        <label style="margin:0; flex:1"><input type="radio" name="qm-mode" value="pqc" checked /> PQC (ML-KEM-768)</label>
        <label style="margin:0; flex:1"><input type="radio" name="qm-mode" value="passphrase" /> Passphrase</label>
      </div>

      <div id="qm-pqc">
        <label>Recipient public key (base64)</label>
        <input id="qm-recipient" placeholder="Paste recipient public key" />
      </div>

      <div id="qm-pw" style="display:none">
        <label>Passphrase</label>
        <input id="qm-passphrase" placeholder="Strong passphrase" />
      </div>

      <div class="row" style="margin-top: 12px">
        <button class="btn" id="qm-encrypt">Encrypt & Generate</button>
        <button class="btn secondary" id="qm-copy">Copy link</button>
      </div>

      <label>Result</label>
      <div id="qm-result" class="out">—</div>
      <div id="qm-status" class="muted" style="margin-top:8px"></div>
    </div>
  `;

  function setStatus(t, isError=false) {
    const s = modal.querySelector('#qm-status');
    s.textContent = t;
    s.className = isError ? 'muted error' : 'muted';
  }

  function getMode() {
    const r = modal.querySelector('input[name="qm-mode"]:checked');
    return r ? r.value : 'pqc';
  }

  function toggleModeUI() {
    const m = getMode();
    modal.querySelector('#qm-pqc').style.display = (m === 'pqc') ? '' : 'none';
    modal.querySelector('#qm-pw').style.display = (m === 'passphrase') ? '' : 'none';
    setStatus('');
    modal.querySelector('#qm-result').textContent = '—';
  }

  modal.addEventListener('change', (e) => {
    if (e.target && e.target.name === 'qm-mode') toggleModeUI();
  });

  modal.addEventListener('click', async (e) => {
    const target = e.target;
    if (!target) return;

    if (target.id === 'qm-close' || target === modal) {
      modal.style.display = 'none';
      return;
    }

    if (target.id === 'qm-copy') {
      const link = modal.querySelector('#qm-result').textContent.trim();
      if (link && link !== '—') {
        await navigator.clipboard.writeText(link);
        setStatus('Copied to clipboard.');
      }
      return;
    }

    if (target.id === 'qm-encrypt') {
      const serverBase = modal.querySelector('#qm-server').value.trim() || 'http://localhost:5173';
      const plaintext = modal.querySelector('#qm-message').value;
      const mode = getMode();
      const recipientPkB64 = modal.querySelector('#qm-recipient').value.trim();
      const passphrase = modal.querySelector('#qm-passphrase').value.trim();

      if (!plaintext.trim()) { setStatus('Please enter a message.', true); return; }
      if (mode === 'pqc' && !recipientPkB64) { setStatus('Paste the recipient public key (base64).', true); return; }
      if (mode === 'passphrase' && !passphrase) { setStatus('Enter a passphrase.', true); return; }

      setStatus('Encrypting…');

      chrome.runtime.sendMessage(
        {
          type: 'QM_ENCRYPT',
          payload: { plaintext, mode, recipientPkB64, passphrase, serverBase }
        },
        (resp) => {
          if (!resp) {
            setStatus('No response from background script. Is the extension loaded?', true);
            return;
          }
          if (!resp.ok) {
            setStatus(resp.error || 'Failed', true);
            return;
          }
          modal.querySelector('#qm-result').textContent = resp.url;
          setStatus('Link generated.');
        }
      );
    }
  });

  btn.addEventListener('click', () => {
    modal.style.display = 'block';
    // load server base from storage
    chrome.storage.sync.get({ serverBase: 'http://localhost:5173' }, (v) => {
      const inp = modal.querySelector('#qm-server');
      if (inp && !inp.value) inp.value = v.serverBase;
    });
    toggleModeUI();
  });

  document.documentElement.appendChild(btn);
  document.documentElement.appendChild(modal);
})();
