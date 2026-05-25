const modeSel = null; // not used

const wsUrlInput = document.getElementById('wsUrl');
const connectBtn = document.getElementById('connectBtn');
const sendBtn = document.getElementById('btnSend');
const consoleEl = document.getElementById('console');

const receiverPublicKeyEl = document.getElementById('receiverPublicKey');

const emailInputEl = document.getElementById('emailInput');
const filenameInputEl = document.getElementById('filenameInput');
const aesKeyInputEl = document.getElementById('aesKeyInput');

const btnHash = document.getElementById('btnHash');
const btnEncryptAES = document.getElementById('btnEncryptAES');
const btnWrapAESKey = document.getElementById('btnWrapAESKey');
const btnSignHash = document.getElementById('btnSignHash');
const btnUseGeneratedAes = document.getElementById('btnUseGeneratedAes');


const hashOutEl = document.getElementById('hashOut');

const senderPrivateKeyEl = document.getElementById('senderPrivateKey');

const btnSend = document.getElementById('btnSend');

let ws = null;

function logLine(msg, kind = 'info') {
  const p = document.createElement('div');
  p.className = 'log ' + (kind === 'ok' ? 'tag-ok' : kind === 'bad' ? 'tag-bad' : 'tag-info');
  p.textContent = msg;
  consoleEl.appendChild(p);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function setEnabled(el, enabled) {
  if (!el) return;
  el.disabled = !enabled;
}

let computed = {
  hashHex: null,
  aesKeyBytes: null,
};

function getAESKeyBytes() {
  const t = (aesKeyInputEl.value || '').trim();
  if (!t) return null;

  // Support hex or base64
  if (/^[0-9a-fA-F]+$/.test(t) && t.length % 2 === 0) {
    return Uint8Array.from(Buffer.from(t, 'hex'));
  }

  // base64
  return Uint8Array.from(Buffer.from(t, 'base64'));
}

function sha512Hex(bytes) {
  // Use Web Crypto SHA-512
  return window.crypto.subtle.digest('SHA-512', bytes).then(buf => {
    const arr = new Uint8Array(buf);
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  });
}

async function computeHash() {
  const text = emailInputEl.value || '';
  const enc = new TextEncoder().encode(text);
  const hex = await sha512Hex(enc);
  computed.hashHex = hex;
  hashOutEl.value = hex;
}

connectBtn.onclick = () => {
  const wsUrl = wsUrlInput.value.trim();
  consoleEl.innerHTML = '';
  logLine(`[ ] Connecting to ${wsUrl} ...`);
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    logLine('[+] WebSocket connected', 'ok');
    ws.send('Hello!');
    ws.send('sender');

    // Unconditionally enable step buttons based on current workflow state
    setEnabled(btnHash, true);
    setEnabled(btnEncryptAES, false);
    setEnabled(btnWrapAESKey, false);
    setEnabled(btnSignHash, false);
    setEnabled(btnSend, false);
  };

  ws.onmessage = async (ev) => {
    let data;
    try { data = JSON.parse(ev.data); } catch { data = ev.data; }

    if (typeof data === 'string') {
      if (data === 'Ready!') logLine('[+] Server: Ready!', 'ok');
      else logLine('[ ] ' + data);
      return;
    }

    if (data.type === 'log') {
      logLine(data.message);
      return;
    }

    if (data.type === 'public_key') {
      logLine('[+] Receiver RSA public key received (backend will use it)', 'ok');
      return;
    }

    if (data.type === 'ACK') {
      logLine(`[+] ACK: ${data.status} saved_as=${data.saved_as}`, 'ok');
      return;
    }

    if (data.type === 'NACK') {
      logLine(`[x] NACK: ${data.reason}`, 'bad');
      return;
    }
  };

  ws.onerror = () => logLine('[x] WebSocket error', 'bad');
  ws.onclose = () => {
    ws = null;
    logLine('[ ] Disconnected');
    setEnabled(btnHash, false);
    setEnabled(btnEncryptAES, false);
    setEnabled(btnWrapAESKey, false);
    setEnabled(btnSignHash, false);
    setEnabled(btnSend, false);
  };
};

btnHash.onclick = async () => {
  if (!emailInputEl.value) return;
  await computeHash();
  logLine('[+] Hash computed (SHA-512)', 'ok');
  setEnabled(btnEncryptAES, true);
};

btnEncryptAES.onclick = () => {
  // Backend will do AES-CBC; UI only triggers step order.
  logLine('[ ] AES encrypt step will be performed by backend', 'info');
  setEnabled(btnWrapAESKey, true);
};

btnWrapAESKey.onclick = () => {
  logLine('[ ] RSA wrap step will be performed by backend', 'info');
  setEnabled(btnSignHash, true);
};

btnSignHash.onclick = () => {
  // Signature uses sender_private_key on backend (it reads the key file).
  logLine('[ ] Signature step will be performed by backend using keys/sender_private_key.pem', 'info');
  setEnabled(btnSend, true);
};

btnSend.onclick = () => {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;

  const plaintext = emailInputEl.value || '';
  const filename = (filenameInputEl.value || 'email.txt').trim();
  const req = {
    type: 'send_request',
    tamper_1_byte: false,
    filename,
    plaintext
  };

  ws.send(JSON.stringify(req));
  logLine('[ ] Sent send_request', 'info');
};

