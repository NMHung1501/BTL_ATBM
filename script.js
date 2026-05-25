const modeSel = document.getElementById('mode');
const wsUrlInput = document.getElementById('wsUrl');
const connectBtn = document.getElementById('connectBtn');
const sendBtn = document.getElementById('sendBtn');
const tamperToggle = document.getElementById('tamperToggle');
const consoleEl = document.getElementById('console');

const senderPrivateKeyEl = document.getElementById('senderPrivateKey');
const senderPublicKeyEl = document.getElementById('senderPublicKey');
const receiverPrivateKeyEl = document.getElementById('receiverPrivateKey');
const receiverPublicKeyEl = document.getElementById('receiverPublicKey');
const receiverExpectedFilenameEl = document.getElementById('receiverExpectedFilename');
const emailInputEl = document.getElementById('emailInput');
const filenameInputEl = document.getElementById('filenameInput');
const savePlaintextBtn = document.getElementById('savePlaintextBtn');
const plainHintEl = document.getElementById('plainHint');


let ws = null;
let role = null;
let readyForSend = false;

function logLine(msg, kind = 'info') {
  const p = document.createElement('div');
  p.className = 'log ' + (kind === 'ok' ? 'tag-ok' : kind === 'bad' ? 'tag-bad' : 'tag-info');
  p.textContent = msg;
  consoleEl.appendChild(p);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function setSendEnabled(enabled) {
  sendBtn.disabled = !enabled;
  readyForSend = enabled;
}

function readKeyText(el) {
  const t = (el?.value || '').trim();
  return t.length ? t : null;
}

function savePlaintextToArtifacts() {
  // We cannot write directly to server artifacts from browser.
  // So we send the plaintext to the backend, which will write artifacts/email.txt.
  const plaintext = emailInputEl.value;
  const filename = (filenameInputEl.value || 'email.txt').trim();

  if (!ws || ws.readyState !== WebSocket.OPEN) {
    logLine('[x] Connect WS first', 'bad');
    return;
  }

  // Only Sender writes plaintext into artifacts via backend.
  ws.send(JSON.stringify({ type: 'save_plaintext_request', filename, plaintext }));
  logLine('[ ] Request: save_plaintext_request', 'info');
}

function connect() {
  role = modeSel.value;
  const wsUrl = wsUrlInput.value.trim();

  consoleEl.innerHTML = '';
  logLine(`[ ] Connecting to ${wsUrl} ...`);

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    logLine('[+] WebSocket connected', 'ok');

    // Protocol Step 1: handshake
    if (role === 'sender') {
      ws.send('Hello!');
      logLine('[ ] Sent: Hello!', 'info');
    } else {
      // receiver: optionally still send role; backend will send Ready
      logLine('[ ] Receiver mode: waiting for server Ready', 'info');
    }

    ws.send(role);
    logLine(`[ ] Sent role=${role}`);

    // UI state
    syncReceiverSenderPanels();
    setSendEnabled(false);
    savePlaintextBtn.disabled = role !== 'sender';

  };

  ws.onmessage = (ev) => {
    let data;
    try {
      data = JSON.parse(ev.data);
    } catch {
      data = ev.data;
    }

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
      // Only receiver_public_key is used by backend, not required from UI.
      logLine('[+] Receiver RSA public key received (server->client)', 'ok');
      if (role === 'sender') {
        // now we can send
        setSendEnabled(true);
      }
      return;
    }

    if (data.type === 'ACK') {
      logLine(`[+] ACK: ${data.status} (saved_as=${data.saved_as})`, 'ok');
      setSendEnabled(false);
      return;
    }

    if (data.type === 'NACK') {
      logLine(`[x] NACK: ${data.reason}`, 'bad');
      setSendEnabled(true);
      return;
    }

    if (data.type === 'saved_plaintext') {
      plainHintEl.textContent = `Saved plaintext to artifacts/email.txt (filename=${data.filename})`;
      logLine(`[+] ${data.message}`, 'ok');
      return;
    }

    logLine('[ ] ' + JSON.stringify(data));
  };

  ws.onerror = () => logLine('[x] WebSocket error', 'bad');
  ws.onclose = () => {
    logLine('[ ] Disconnected');
    ws = null;
    setSendEnabled(false);
    savePlaintextBtn.disabled = true;
  };
}

function send() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  if (role !== 'sender') return;
  if (!readyForSend) return;

  // Keys fields are optional because backend reads from keys/*.pem.
  // We still include them in request if you want backend to overwrite keys from UI.
  // (Backend supports optional update only if implemented; otherwise they are ignored.)

  const tamper = !!tamperToggle.checked;
  const filename = (filenameInputEl.value || 'email.txt').trim();
  const plaintext = emailInputEl.value;

  // Ensure artifacts have plaintext: write/update it before sending.
  // Backend will handle plaintext update, then encrypt+send.
  const req = {
    type: 'send_request',
    tamper_1_byte: tamper,
    filename,
    plaintext
  };

  ws.send(JSON.stringify(req));
  logLine(`[ ] Sending encrypted_packet (tamper_1_byte=${tamper}) ...`);
}

connectBtn.onclick = connect;
sendBtn.onclick = send;
savePlaintextBtn.onclick = savePlaintextToArtifacts;

function syncReceiverSenderPanels(){
  const isSender = role === 'sender';
  document.getElementById('senderPanel').style.display = isSender ? 'block' : 'none';
  document.getElementById('receiverPanel').style.display = isSender ? 'none' : 'block';
}

// initial UI
setSendEnabled(false);
// sender/receiver panel swap is handled on connect once role known
plainHintEl.textContent = '';


