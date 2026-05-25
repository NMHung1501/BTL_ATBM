# TODO

- [ ] Create full project structure (backend + frontend + keys + artifacts placeholder)
- [ ] Implement `crypto_utils.py` with AES-CBC, RSA PKCS#1 v1.5 + SHA-512 signature, deterministic metadata serialization, hash SHA-512(IV||cipher||exp)
- [ ] Implement `app.py` FastAPI WebSocket `/ws` with strict protocol/state machine, ACK/NACK, role enforcement, tamper 1 byte mode
- [ ] Create `requirements.txt`
- [ ] Create frontend: `index.html`, `style.css`, `script.js` with Sender/Receiver toggle, connect/send UI, tamper checkbox, real-time console logs
- [ ] Create `README.md` with clear LAN 2-machine instructions and firewall notes, key copy requirement
- [ ] Generate initial sender keypair (on first run) and persist to `keys/`
- [ ] Create artifacts on Sender encrypt stage (`aes_cipher.bin`, `aes_iv.bin`, `packet.json`)
- [ ] Run end-to-end test locally (2 instances) and validate NACK reason is `Hash Mismatch` in tamper mode
- [ ] Produce final explanation file (simple, easy-to-understand) covering functions/flow/features

