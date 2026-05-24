const els = (sel) => document.querySelector(sel);
const logEl = els('#log');

function logLine(text, type = 'info') {
  const div = document.createElement('div');
  div.className = 'line';

  const tag = document.createElement('span');
  tag.className = `tag ${type === 'plus' ? 'plus' : type === 'warn' ? 'warn' : 'dot'}`;
  tag.textContent = type === 'plus' ? '[+]' : type === 'warn' ? '[!]' : '[.]';
  div.appendChild(tag);

  const span = document.createElement('span');
  span.textContent = ' ' + text;
  div.appendChild(span);

  logEl.appendChild(div);
  logEl.scrollTop = logEl.scrollHeight;
}

function clearLog() {
  logEl.innerHTML = '';
}

let ws = null;
let role = 'sender';

function currentExpIso() {
  const expInput = els('#exp').value.trim();
  if (!expInput) return null;

  if (expInput.toLowerCase().startsWith('auto')) {
    const exp = new Date(Date.now() + 24 * 60 * 60 * 1000);
    return exp.toISOString();
  }

  const d = new Date(expInput);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

function fileToBytes(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

function bytesToBase64(u8) {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < u8.length; i += chunk) {
    s += String.fromCharCode(...u8.subarray(i, i + chunk));
  }
  return btoa(s);
}

els('input[name="mode"]').addEventListener('change', () => {
  role = document.querySelector('input[name="mode"]:checked').value;

  els('#receiverBox').classList.toggle('hidden', role !== 'receiver');
  els('#senderBox').classList.toggle('hidden', role !== 'sender');
  els('#btnSend').disabled = true;

  logLine(`Chế độ: ${role}`, 'info');
});

els('#btnClear').addEventListener('click', () => clearLog());

els('#btnConnect').addEventListener('click', async () => {
  if (ws) {
    ws.close();
    ws = null;
  }

  const wsUrl = els('#wsUrl').value.trim();
  if (!wsUrl) {
    logLine('WS URL rỗng', 'warn');
    return;
  }

  logLine('Đang kết nối WebSocket...', 'info');
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    logLine('Kết nối OK', 'plus');
    ws.send(role === 'sender' ? 'Hello!' : 'Receiver!');
  };

  ws.onmessage = (ev) => {
    const msg = ev.data;
    if (typeof msg !== 'string') return;

    if (msg === 'Ready!') {
      logLine('Handshake: Ready!', 'plus');
      return;
    }

    try {
      const data = JSON.parse(msg);

      if (data.type === 'public_key') {
        logLine('Receiver gửi Public Key RSA', 'plus');
        els('#btnSend').disabled = false;
        return;
      }

      if (data.type === 'ACK') {
        logLine(`ACK: ${data.status} (saved_as=${data.saved_as})`, 'plus');
        els('#btnSend').disabled = false;
        return;
      }

      if (data.type === 'NACK') {
        logLine(`NACK: ${data.reason}`, 'warn');
        els('#btnSend').disabled = false;
        return;
      }

      logLine('JSON: ' + msg, 'info');
    } catch {
      logLine('Message: ' + msg, 'info');
    }
  };

  ws.onclose = () => {
    logLine('WebSocket đóng', 'warn');
    ws = null;
  };

  ws.onerror = () => {
    logLine('WebSocket lỗi', 'warn');
  };
});

els('#btnSend').addEventListener('click', async () => {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    logLine('Chưa kết nối WebSocket', 'warn');
    return;
  }
  if (role !== 'sender') {
    logLine('Chỉ Sender mới gửi', 'warn');
    return;
  }

  const filename = els('#filename').value.trim() || 'email.txt';
  const expIso = currentExpIso();
  const file = els('#fileInput').files?.[0];

  if (!file) {
    logLine('Chưa chọn file', 'warn');
    return;
  }
  if (!expIso) {
    logLine('Expiration ISO không hợp lệ', 'warn');
    return;
  }

  logLine('[+] Bắt đầu: tạo payload -> backend thực hiện RSA/AES/SHA theo yêu cầu', 'plus');

  try {
    const bytes = await fileToBytes(file);
    const plaintextB64 = bytesToBase64(bytes);

    els('#btnSend').disabled = true;

    ws.send(JSON.stringify({ filename, plaintext_b64: plaintextB64, exp: expIso }));
    logLine('[+] Gửi plaintext_b64 + metadata exp/filename sang backend', 'info');
  } catch (e) {
    logLine('Gửi thất bại: ' + e, 'warn');
    els('#btnSend').disabled = false;
  }
});

els('#receiverBox').classList.toggle('hidden', role !== 'receiver');
els('#senderBox').classList.toggle('hidden', role !== 'sender');

