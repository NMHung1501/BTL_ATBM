// ============================================================
// CipherChat — Frontend Logic (Commercial Version)
// ============================================================

(() => {
  'use strict';

  // ── DOM refs ──
  const loginOverlay = document.getElementById('loginOverlay');
  const usernameInput = document.getElementById('usernameInput');
  const joinBtn = document.getElementById('joinBtn');
  const loginError = document.getElementById('loginError');

  const appShell = document.getElementById('appShell');
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const headerAvatar = document.getElementById('headerAvatar');
  const headerUsername = document.getElementById('headerUsername');
  const userCount = document.getElementById('userCount');
  const userList = document.getElementById('userList');

  const chatMessages = document.getElementById('chatMessages');
  const emptyState = document.getElementById('emptyState');
  const messageInput = document.getElementById('messageInput');
  const sendBtn = document.getElementById('sendBtn');

  const cryptoPanel = document.getElementById('cryptoPanel');
  const cryptoPanelClose = document.getElementById('cryptoPanelClose');
  const cryptoGrid = document.getElementById('cryptoGrid');
  const cryptoBadgeBtn = document.getElementById('cryptoBadgeBtn');

  // Share Modal refs
  const shareBtn = document.getElementById('shareBtn');
  const shareOverlay = document.getElementById('shareOverlay');
  const shareCloseBtn = document.getElementById('shareCloseBtn');
  const qrcodeContainer = document.getElementById('qrcode');
  const shareLinkInput = document.getElementById('shareLinkInput');
  const copyLinkBtn = document.getElementById('copyLinkBtn');
  const copyToast = document.getElementById('copyToast');

  // ── State ──
  let ws = null;
  let myUsername = '';
  let reconnectTimer = null;
  let messageCount = 0;
  
  // Auto-detect Server URL based on where the HTML is served from
  const wsUrl = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
    return protocol + window.location.host + '/ws';
  };

  // ── Avatar helper ──
  function getInitial(name) {
    return (name || '?').charAt(0).toUpperCase();
  }

  // Premium Gradients for avatars
  const avatarGradients = [
    'linear-gradient(135deg, #00C9FF 0%, #92FE9D 100%)',
    'linear-gradient(135deg, #f5af19 0%, #f12711 100%)',
    'linear-gradient(135deg, #b224ef 0%, #7579ff 100%)',
    'linear-gradient(135deg, #16A085 0%, #F4D03F 100%)',
    'linear-gradient(135deg, #FF416C 0%, #FF4B2B 100%)',
    'linear-gradient(135deg, #00B4DB 0%, #0083B0 100%)',
  ];

  function getAvatarGradient(name) {
    let hash = 0;
    for (let i = 0; i < name.length; i++) {
      hash = name.charCodeAt(i) + ((hash << 5) - hash);
    }
    return avatarGradients[Math.abs(hash) % avatarGradients.length];
  }

  // ── Time formatter ──
  function formatTime(isoStr) {
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' });
    } catch {
      return '';
    }
  }

  // ── Share / QR Logic ──
  let qrCodeGenerated = false;

  function initShareModal() {
    const shareUrl = window.location.href;
    shareLinkInput.value = shareUrl;

    if (!qrCodeGenerated && typeof QRCode !== 'undefined') {
      new QRCode(qrcodeContainer, {
        text: shareUrl,
        width: 180,
        height: 180,
        colorDark : "#ffffff",
        colorLight : "#1a1b26", // match dark theme
        correctLevel : QRCode.CorrectLevel.H
      });
      qrCodeGenerated = true;
    }
  }

  shareBtn.addEventListener('click', () => {
    initShareModal();
    shareOverlay.classList.remove('hidden');
    // slight delay for animation
    setTimeout(() => shareOverlay.classList.add('active'), 10);
  });

  shareCloseBtn.addEventListener('click', () => {
    shareOverlay.classList.remove('active');
    setTimeout(() => shareOverlay.classList.add('hidden'), 300);
  });

  copyLinkBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(shareLinkInput.value).then(() => {
      copyToast.classList.add('show');
      setTimeout(() => copyToast.classList.remove('show'), 2000);
    });
  });

  // ── UI state transitions ──
  function showApp() {
    loginOverlay.classList.remove('active');
    setTimeout(() => {
      loginOverlay.classList.add('hidden');
      appShell.classList.remove('hidden');
      // small delay for css transition
      setTimeout(() => appShell.classList.add('active'), 50);
      
      headerAvatar.textContent = getInitial(myUsername);
      headerAvatar.style.background = getAvatarGradient(myUsername);
      headerUsername.textContent = myUsername;
      messageInput.focus();
    }, 400); // match css transition time
  }

  function setConnected(connected) {
    if (connected) {
      statusDot.classList.add('online');
      statusText.textContent = 'Đã kết nối';
      sendBtn.disabled = false;
    } else {
      statusDot.classList.remove('online');
      statusText.textContent = 'Mất kết nối';
      sendBtn.disabled = true;
    }
  }

  function setLoginError(msg) {
    loginError.textContent = msg;
  }

  // ── Render user list ──
  function renderUserList(users) {
    userList.innerHTML = '';
    const count = users.length;
    userCount.textContent = `${count} người`;

    users.forEach(name => {
      const item = document.createElement('div');
      item.className = 'user-item glass-panel-inner';

      const avatar = document.createElement('div');
      avatar.className = 'user-item__avatar';
      avatar.textContent = getInitial(name);
      avatar.style.background = getAvatarGradient(name);

      const nameEl = document.createElement('span');
      nameEl.className = 'user-item__name';
      nameEl.textContent = name;

      item.appendChild(avatar);
      item.appendChild(nameEl);

      if (name === myUsername) {
        const youTag = document.createElement('span');
        youTag.className = 'user-item__you glass-badge';
        youTag.textContent = 'Bạn';
        item.appendChild(youTag);
      }

      userList.appendChild(item);
    });
  }

  // ── Add system message ──
  function addSystemMessage(text) {
    hideEmptyState();
    const div = document.createElement('div');
    div.className = 'system-message';
    const inner = document.createElement('span');
    inner.className = 'system-message__text';
    inner.textContent = text;
    div.appendChild(inner);
    chatMessages.appendChild(div);
    scrollToBottom();
  }

  // ── Add chat message ──
  function addMessage(from, text, timestamp, cryptoDetail, isSent) {
    hideEmptyState();
    messageCount++;

    const wrapper = document.createElement('div');
    wrapper.className = `message message--${isSent ? 'sent' : 'received'}`;
    wrapper.id = `msg-${messageCount}`;

    // Bubble
    const bubbleWrapper = document.createElement('div');
    bubbleWrapper.className = 'message__bubble-wrapper';

    // Sender name
    if (!isSent) {
      const senderEl = document.createElement('div');
      senderEl.className = 'message__sender';
      senderEl.textContent = from;
      bubbleWrapper.appendChild(senderEl);
    }

    const bubble = document.createElement('div');
    bubble.className = 'message__bubble';
    bubble.textContent = text;
    bubbleWrapper.appendChild(bubble);

    // Meta row
    const meta = document.createElement('div');
    meta.className = 'message__meta';

    const timeEl = document.createElement('span');
    timeEl.className = 'message__time';
    timeEl.textContent = formatTime(timestamp);
    meta.appendChild(timeEl);

    // Lock icon with crypto detail
    if (cryptoDetail) {
      const lock = document.createElement('span');
      lock.className = 'message__lock';
      lock.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="12" height="12"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>';
      lock.setAttribute('role', 'button');
      lock.setAttribute('aria-label', 'Chi tiết bảo mật');

      lock.addEventListener('click', () => showCryptoDetail(cryptoDetail));
      meta.appendChild(lock);
    }

    bubbleWrapper.appendChild(meta);
    wrapper.appendChild(bubbleWrapper);
    
    chatMessages.appendChild(wrapper);
    
    // trigger animation
    setTimeout(() => wrapper.classList.add('appear'), 10);
    scrollToBottom();
  }

  function hideEmptyState() {
    if (emptyState) {
      emptyState.style.display = 'none';
    }
  }

  function scrollToBottom() {
    requestAnimationFrame(() => {
      chatMessages.scrollTop = chatMessages.scrollHeight;
    });
  }

  // ── Crypto Detail Panel ──
  function showCryptoDetail(detail) {
    cryptoGrid.innerHTML = '';

    const fields = [
      { label: 'Thuật toán', value: detail.algorithm || 'AES-256-CBC + RSA-2048 + SHA-512', cls: '' },
      { label: 'Chữ ký số (RSA)', value: detail.signature_status === 'verified' ? '✅ Đã xác thực' : '❌ Không hợp lệ', cls: detail.signature_status === 'verified' ? 'crypto-field__value--ok' : 'crypto-field__value--bad' },
      { label: 'Toàn vẹn Hash (SHA-512)', value: detail.hash_status === 'match' ? '✅ Khớp' : '❌ Không khớp', cls: detail.hash_status === 'match' ? 'crypto-field__value--ok' : 'crypto-field__value--bad' },
      { label: 'Mã Hash SHA-512', value: detail.hash || '—', cls: '' },
      { label: 'Vector khởi tạo (IV)', value: detail.iv_hex || '—', cls: '' },
      { label: 'Hạn dùng gói tin (Exp)', value: detail.exp || '—', cls: '' },
    ];

    fields.forEach(f => {
      const field = document.createElement('div');
      field.className = 'crypto-field';

      const label = document.createElement('div');
      label.className = 'crypto-field__label';
      label.textContent = f.label;

      const value = document.createElement('div');
      value.className = 'crypto-field__value' + (f.cls ? ' ' + f.cls : '');
      value.textContent = f.value;

      field.appendChild(label);
      field.appendChild(value);
      cryptoGrid.appendChild(field);
    });

    cryptoPanel.classList.remove('hidden');
    setTimeout(() => cryptoPanel.classList.add('active'), 10);
  }

  function hideCryptoPanel() {
    cryptoPanel.classList.remove('active');
    setTimeout(() => cryptoPanel.classList.add('hidden'), 300);
  }

  cryptoPanelClose.addEventListener('click', hideCryptoPanel);
  cryptoPanel.addEventListener('click', (e) => {
    if (e.target === cryptoPanel) hideCryptoPanel();
  });
  
  if (cryptoBadgeBtn) {
      cryptoBadgeBtn.addEventListener('click', () => {
          showCryptoDetail({
              algorithm: 'Mọi tin nhắn đều được mã hóa',
              signature_status: 'verified',
              hash_status: 'match',
              hash: 'Tạo ngẫu nhiên mỗi tin nhắn',
              iv_hex: 'Tạo ngẫu nhiên mỗi tin nhắn',
              exp: 'Tạo ngẫu nhiên mỗi tin nhắn'
          });
      });
  }

  // ── WebSocket ──
  function connect() {
    if (ws && ws.readyState <= WebSocket.OPEN) {
      ws.close();
    }

    const url = wsUrl();
    ws = new WebSocket(url);

    ws.onopen = () => {
      // Bắt đầu quy trình Handshake (Đề tài 1)
      ws.send(JSON.stringify({ type: 'handshake', text: 'Hello!' }));
    };

    ws.onmessage = (ev) => {
      let data;
      try {
        data = JSON.parse(ev.data);
      } catch {
        return;
      }

      switch (data.type) {
        case 'handshake_reply':
          if (data.text === 'Ready!') {
            // Handshake thành công, tiến hành register
            ws.send(JSON.stringify({ type: 'register', username: myUsername }));
          }
          break;

        case 'registered':
          setConnected(true);
          showApp();
          addSystemMessage(`🎉 ${data.message} (Handshake OK)`);
          break;

        case 'error':
          if (!appShell.classList.contains('active')) {
            setLoginError(data.message);
            joinBtn.disabled = false;
            joinBtn.innerHTML = 'Tham gia ngay';
          } else {
            addSystemMessage(`⚠️ ${data.message}`);
          }
          break;

        case 'system':
          addSystemMessage(data.message);
          break;

        case 'user_list':
          renderUserList(data.users || []);
          break;

        case 'message_sent':
          addMessage(
            data.from,
            data.text,
            data.timestamp,
            data.crypto_detail,
            true
          );
          break;

        case 'message_received':
          addMessage(
            data.from,
            data.text,
            data.timestamp,
            data.crypto_detail,
            false
          );
          // Play sound directly
          try {
             const audio = new Audio('data:audio/mp3;base64,//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq'); // silent stub, use real sound in production or oscillator
             // Using simple oscillator for futuristic sound
             const ctx = new (window.AudioContext || window.webkitAudioContext)();
             const osc = ctx.createOscillator();
             const gain = ctx.createGain();
             osc.connect(gain);
             gain.connect(ctx.destination);
             osc.type = 'sine';
             osc.frequency.setValueAtTime(880, ctx.currentTime);
             osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.1);
             gain.gain.setValueAtTime(0, ctx.currentTime);
             gain.gain.linearRampToValueAtTime(0.3, ctx.currentTime + 0.05);
             gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.3);
             osc.start(ctx.currentTime);
             osc.stop(ctx.currentTime + 0.3);
          } catch(e) {}
          break;

        case 'pong':
          break;

        default:
          console.log('Unknown message type:', data);
      }
    };

    ws.onerror = () => {
      setConnected(false);
      if (!appShell.classList.contains('active')) {
        setLoginError('Không thể kết nối tới server. Vui lòng thử lại.');
        joinBtn.disabled = false;
        joinBtn.innerHTML = 'Tham gia ngay';
      }
    };

    ws.onclose = () => {
      setConnected(false);
      if (myUsername && appShell.classList.contains('active')) {
        addSystemMessage('🔌 Mất kết nối. Đang thử kết nối lại...');
        clearTimeout(reconnectTimer);
        reconnectTimer = setTimeout(() => {
          connect();
        }, 3000);
      }
    };
  }

  function sendMessage() {
    const text = messageInput.value.trim();
    if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;

    ws.send(JSON.stringify({ type: 'message', text }));
    messageInput.value = '';
    messageInput.style.height = 'auto';
    messageInput.focus();
  }

  // ── Event listeners ──

  joinBtn.addEventListener('click', () => {
    const name = usernameInput.value.trim();
    if (!name) {
      setLoginError('Vui lòng nhập tên hiển thị');
      usernameInput.focus();
      return;
    }
    if (name.length > 20) {
      setLoginError('Tên tối đa 20 ký tự');
      return;
    }

    myUsername = name;
    setLoginError('');
    joinBtn.disabled = true;
    joinBtn.innerHTML = '<span class="spinner"></span> Đang kết nối...';
    connect();
  });

  usernameInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      joinBtn.click();
    }
  });

  sendBtn.addEventListener('click', sendMessage);

  messageInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });

  // Auto-resize textarea
  messageInput.addEventListener('input', () => {
    messageInput.style.height = 'auto';
    messageInput.style.height = Math.min(messageInput.scrollHeight, 120) + 'px';
  });

  // Keep alive
  setInterval(() => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'ping' }));
    }
  }, 30000);

})();
