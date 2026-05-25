let ws = null;

const wsUrlInput = document.getElementById('wsUrl');
const connectBtn = document.getElementById('connectBtn');
const consoleEl = document.getElementById('console');
const packetInputEl = document.getElementById('packetInput');
const btnProcessPacket = document.getElementById('btnProcessPacket');

const integrityResultEl = document.getElementById('integrityResult');
const aesKeyOutEl = document.getElementById('aesKeyOut');
const plainOutEl = document.getElementById('plainOut');
const hashFromSigEl = document.getElementById('hashFromSig');
const hashRecomputedEl = document.getElementById('hashRecomputed');

const receiverPrivateKeyEl = document.getElementById('receiverPrivateKey');
const senderPublicKeyEl = document.getElementById('senderPublicKey');

function logLine(msg, kind = 'info') {
  const p = document.createElement('div');
  p.className = 'log ' + (kind === 'ok' ? 'tag-ok' : kind === 'bad' ? 'tag-bad' : 'tag-info');
  p.textContent = msg;
  consoleEl.appendChild(p);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function setText(el, v) {
  if (!el) return;
  el.value = v ?? '';
}

function resetResults(){
  setText(aesKeyOutEl, '');
  setText(plainOutEl, '');
  setText(hashFromSigEl, '');
  setText(hashRecomputedEl, '');
  if (integrityResultEl) integrityResultEl.textContent = '';
}

connectBtn && (connectBtn.onclick = () => {
  const wsUrl = wsUrlInput.value.trim();
  consoleEl.innerHTML = '';
  resetResults();
  logLine(`[ ] Connecting to ${wsUrl} ...`);
  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    logLine('[+] WebSocket connected', 'ok');
    ws.send('receiver');
  };

  ws.onmessage = (ev) => {
    let data;
    try { data = JSON.parse(ev.data); } catch { data = ev.data; }

    if (typeof data === 'string') {
      logLine('[ ] ' + data);
      return;
    }

    if (data.type === 'log') {
      logLine(data.message);
      return;
    }

    if (data.type === 'public_key') {
      logLine('[ ] (Receiver role) public_key received - ignored', 'info');
      return;
    }

    if (data.type === 'ACK') {
      logLine(`[+] ACK: ${data.status}`, 'ok');
      return;
    }

    if (data.type === 'NACK') {
      logLine(`[x] NACK: ${data.reason}`, 'bad');
      integrityResultEl.textContent = data.reason;
      return;
    }
  };

  ws.onerror = () => logLine('[x] WebSocket error', 'bad');
  ws.onclose = () => logLine('[ ] Disconnected');
});

// ===== Offline manual decrypt+verify UI (manual steps, but single button) =====
const ivInputEl = document.getElementById('ivInput');
const cipherInputEl = document.getElementById('cipherInput');
const encSessionKeyInputEl = document.getElementById('encSessionKeyInput');
const hashInputEl = document.getElementById('hashInput');
const sigInputEl = document.getElementById('sigInput');
const expInputEl = document.getElementById('expInput');
const filenameInputEl = document.getElementById('filenameInput');

function getVal(el){ return (el?.value || '').trim(); }

function setIntegrity(msg, kind){
  if(!integrityResultEl) return;
  integrityResultEl.textContent = msg;
  integrityResultEl.className = kind === 'ok' ? 'hint tag-ok' : kind === 'bad' ? 'hint tag-bad' : 'hint';
}

function validateForEnable(){
  if(!btnProcessPacket) return;
  const iv = getVal(ivInputEl);
  const cipher = getVal(cipherInputEl);
  const encKey = getVal(encSessionKeyInputEl);
  const hash = getVal(hashInputEl);
  const sig = getVal(sigInputEl);
  const exp = getVal(expInputEl);
  const priv = getVal(receiverPrivateKeyEl);
  const senderPub = getVal(senderPublicKeyEl);

  const ok = iv && cipher && encKey && hash && sig && exp && priv && senderPub;
  btnProcessPacket.disabled = !ok;
}

[ivInputEl, cipherInputEl, encSessionKeyInputEl, hashInputEl, sigInputEl, expInputEl, receiverPrivateKeyEl, senderPublicKeyEl].forEach(el => {
  el && el.addEventListener('input', validateForEnable);
});
validateForEnable();

btnProcessPacket && (btnProcessPacket.onclick = async () => {
  try {
    resetResults();
    if (!btnProcessPacket) return;

    const ivB64 = getVal(ivInputEl);
    const cipherB64 = getVal(cipherInputEl);
    const encSessionKeyB64 = getVal(encSessionKeyInputEl);
    const hashHex = getVal(hashInputEl);
    const sigB64 = getVal(sigInputEl);
    const expIso = getVal(expInputEl);
    const filename = getVal(filenameInputEl) || 'email.txt';

    const receiverPrivatePem = getVal(receiverPrivateKeyEl).trim();
    const senderPublicPem = getVal(senderPublicKeyEl).trim();

    logLine('[+] Offline Step 1: check exp (timeout) ...');
    // expIso dạng ISO-8601 UTC ...Z. new Date() thường đúng, nhưng để tránh mismatch timezone/format,
    // parse theo timestamp ms.
    const expMs = Date.parse(expIso);
    const nowMs = Date.now();
    if (!Number.isFinite(expMs)) {
      setIntegrity('Invalid exp format', 'bad');
      logLine('[x] Invalid exp format', 'bad');
      return;
    }
    const expirationDeadline = expMs + (24 * 60 * 60 * 1000); 

    if (!(nowMs <= expirationDeadline)) {
      setIntegrity('Timeout/Expired', 'bad');
      logLine('[x] Timeout/Expired', 'bad');
      return;
    }

    logLine('[+] Offline Step 2: base64 decode (iv/cipher/enc_session_key/sig) ...');

    const ivBytes = b64ToBytes(ivB64);
    const cipherBytes = b64ToBytes(cipherB64);
    const encSessionKeyBytes = b64ToBytes(encSessionKeyB64);
    const sigBytes = b64ToBytes(sigB64);

    logLine('[+] Offline Step 3: build metadata bytes + verify RSA signature ...');
    const metadataBytes = metadataDeterministicBytes(filename, expIso);
    const sigOk = rsaVerifyMetadataSha512Pkcs1v15(metadataBytes, sigBytes, senderPublicPem);
    if (!sigOk) {
      setIntegrity('Invalid Signature/Integrity', 'bad');
      logLine('[x] Invalid Signature/Integrity', 'bad');
      return;
    }

    logLine('[+] Offline Step 4: recompute integrity hash ...');
    const actualHash = await sha512Hex(new Uint8Array([...ivBytes, ...cipherBytes, ...new TextEncoder().encode(expIso)]));
    if (actualHash.toLowerCase() !== hashHex.toLowerCase()) {
      setIntegrity('Hash Mismatch', 'bad');
      logLine('[x] Hash Mismatch', 'bad');
      setText(hashFromSigEl, hashHex);
      setText(hashRecomputedEl, actualHash);
      return;
    }

    setText(hashFromSigEl, hashHex);
    setText(hashRecomputedEl, actualHash);

    logLine('[+] Offline Step 5: RSA decrypt enc_session_key -> AES key ...');
    const aesKeyBytes = rsaDecryptPkcs1v15(encSessionKeyBytes, receiverPrivatePem);
    const aesKeyHex = [...aesKeyBytes].map(b => b.toString(16).padStart(2, '0')).join('');
    setText(aesKeyOutEl, aesKeyHex);

    logLine('[+] Offline Step 6: AES-CBC decrypt cipher -> plaintext ...');
    const plaintextBytes = await aes256CbcDecryptPkcs7(cipherBytes, aesKeyBytes, ivBytes);
    const plaintext = new TextDecoder().decode(plaintextBytes);

    setText(plainOutEl, plaintext);
    setIntegrity('Integrity OK + Signature OK', 'ok');
    logLine('[+] Offline decrypt+verify Success', 'ok');
  } catch (e) {
    console.error(e);
    setIntegrity('Error: ' + (e?.message || e), 'bad');
    logLine('[x] Offline error: ' + (e?.message || e), 'bad');
  }
});

