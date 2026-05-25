import json
import os
from datetime import datetime, timedelta, timezone

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from crypto_utils import (
    aes256_cbc_decrypt,
    aes256_cbc_encrypt,
    b64d,
    b64e,
    deterministic_metadata_bytes,
    exp_is_valid,
    ensure_dir,
    packet_hash_sha512,
    rsa_decrypt_pkcs1v15,
    rsa_encrypt_pkcs1v15,
    rsa_load_private_key_pem,
    rsa_load_public_key_pem,
    rsa_sign_metadata_sha512_pkcs1v15,
    rsa_verify_metadata_sha512_pkcs1v15,
    tamper_one_byte,
)

app = FastAPI()

KEYS_DIR = "keys"
ARTIFACTS_DIR = "artifacts"

SENDER_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "sender_private_key.pem")
SENDER_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "sender_public_key.pem")

RECEIVER_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "receiver_private_key.pem")
RECEIVER_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "receiver_public_key.pem")


def _isoZ_plus_seconds(seconds: int) -> str:
    dt = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=seconds)
    return dt.isoformat().replace("+00:00", "Z")


def generate_sender_keypair_if_needed() -> None:
    ensure_dir(KEYS_DIR)
    if os.path.exists(SENDER_PRIVATE_KEY_PATH) and os.path.exists(SENDER_PUBLIC_KEY_PATH):
        return

    key = RSA.generate(2048)
    private_pem = key.export_key(format="PEM")
    public_pem = key.publickey().export_key(format="PEM")

    with open(SENDER_PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_pem)
    with open(SENDER_PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_pem)


def generate_receiver_keypair_if_needed() -> None:
    ensure_dir(KEYS_DIR)
    if os.path.exists(RECEIVER_PRIVATE_KEY_PATH) and os.path.exists(RECEIVER_PUBLIC_KEY_PATH):
        return

    key = RSA.generate(2048)
    private_pem = key.export_key(format="PEM")
    public_pem = key.publickey().export_key(format="PEM")

    with open(RECEIVER_PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_pem)
    with open(RECEIVER_PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_pem)


def _read_plaintext_from_disk() -> bytes:
    ensure_dir(ARTIFACTS_DIR)
    candidates = [
        os.path.join(ARTIFACTS_DIR, "plain_email.txt"),
        os.path.join(ARTIFACTS_DIR, "email.txt"),
    ]
    for pth in candidates:
        if os.path.exists(pth):
            with open(pth, "rb") as f:
                return f.read()
    return b""


@app.get("/")
def index():
    return HTMLResponse("WS file transfer running. Open index.html on Sender side.")


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()

    try:
        sender_hello_ok = False
        role = None  # "sender" | "receiver"
        receiver_rsa_key = None

        # Step 1: Handshake (expect Sender: "Hello!")
        first_msg = await ws.receive_text()
        if first_msg == "Hello!":
            sender_hello_ok = True
            await ws.send_text("Ready!")

        # Step 1b: Role assignment (Sender sends "sender", Receiver sends "receiver")
        while role is None:
            m = await ws.receive_text()
            if m in ("sender", "receiver"):
                role = m

        if role == "receiver" and not sender_hello_ok:
            await ws.send_text("Ready!")

        if role == "receiver":
            # Step 2: Receiver creates RSA keypair and sends public key PEM to Sender
            receiver_rsa_key = RSA.generate(2048)
            receiver_public_key_pem = receiver_rsa_key.publickey().export_key(format="PEM").decode("utf-8")
            await ws.send_text(json.dumps({"type": "public_key", "public_key_pem": receiver_public_key_pem}))

            # Receiver must load sender public key from keys/sender_public_key.pem
            try:
                sender_public_key = rsa_load_public_key_pem(SENDER_PUBLIC_KEY_PATH)
            except FileNotFoundError:
                await ws.send_text(json.dumps({"type": "NACK", "reason": "Missing sender_public_key.pem"}))
                return

            # Receive encrypted packet
            while True:
                incoming = await ws.receive_text()
                try:
                    data = json.loads(incoming)
                except json.JSONDecodeError:
                    await ws.send_text(json.dumps({"type": "NACK", "reason": "Invalid JSON"}))
                    continue

                if data.get("type") != "encrypted_packet":
                    await ws.send_text(json.dumps({"type": "NACK", "reason": "Unexpected message type"}))
                    continue

                await ws.send_text(json.dumps({"type": "log", "message": "[+] Đang verify hash/chữ ký + ACK/NACK"}))

                exp_iso = data.get("exp")
                if not exp_iso or not exp_is_valid(exp_iso):
                    await ws.send_text(json.dumps({"type": "NACK", "reason": "Timeout/Expired"}))
                    continue

                try:
                    iv = b64d(data["iv"])
                    ciphertext = b64d(data["cipher"])
                    sig = b64d(data["sig"])
                    enc_session_key = b64d(data["enc_session_key"])
                    filename = data.get("filename", "email.txt")
                except Exception:
                    await ws.send_text(json.dumps({"type": "NACK", "reason": "Invalid packet encoding"}))
                    continue

                # Verify signature over deterministic metadata
                metadata = {"filename": filename, "exp": exp_iso}
                metadata_bytes = deterministic_metadata_bytes(metadata)

                sig_ok = rsa_verify_metadata_sha512_pkcs1v15(metadata_bytes, sig, sender_public_key)
                if not sig_ok:
                    await ws.send_text(json.dumps({"type": "NACK", "reason": "Invalid Signature/Integrity"}))
                    continue

                # Verify hash integrity: SHA-512(IV || ciphertext || exp)
                actual_hash = packet_hash_sha512(iv, ciphertext, exp_iso)
                if str(data.get("hash")).lower() != actual_hash.lower():
                    await ws.send_text(json.dumps({"type": "NACK", "reason": "Hash Mismatch"}))
                    continue

                # Decrypt AES key and ciphertext
                try:
                    aes_key = rsa_decrypt_pkcs1v15(enc_session_key, receiver_rsa_key)
                    plaintext = aes256_cbc_decrypt(ciphertext, aes_key, iv)
                except Exception:
                    await ws.send_text(json.dumps({"type": "NACK", "reason": "Decrypt Failed"}))
                    continue

                ensure_dir(ARTIFACTS_DIR)
                out_path = os.path.join(ARTIFACTS_DIR, filename)
                with open(out_path, "wb") as f:
                    f.write(plaintext)

                await ws.send_text(json.dumps({"type": "ACK", "status": "Success", "saved_as": filename}))

        elif role == "sender":
            generate_sender_keypair_if_needed()
            generate_receiver_keypair_if_needed()

            # Load receiver public key from file
            try:
                receiver_public_key = rsa_load_public_key_pem(RECEIVER_PUBLIC_KEY_PATH)
            except FileNotFoundError:
                await ws.send_text(json.dumps({"type": "NACK", "reason": "Missing receiver_public_key.pem"}))
                return

            # Sender waits for send_request
            while True:
                incoming = await ws.receive_text()
                try:
                    req = json.loads(incoming)
                except json.JSONDecodeError:
                    continue
                if req.get("type") != "send_request":
                    continue

# tamper mode removed (manual integrity test via editing artifacts/packet.json or aes_cipher.bin)
                packet_tamper_requested = False
                filename = (req.get("filename") or "email.txt").strip()
                # Tăng TTL để tránh demo/round-trip chậm bị Timeout/Expired
                # exp dùng như thời hạn để receiver chấp nhận (demo theo yêu cầu: 24h)
                exp_iso = _isoZ_plus_seconds(0)



                metadata = {"filename": filename, "exp": exp_iso}
                metadata_bytes = deterministic_metadata_bytes(metadata)

                # AES session key + IV (prefer fixed key if exists)
                fixed_aes_key_path = os.path.join(KEYS_DIR, "fixed_aes_key.bin")
                fixed_aes_key = None
                if os.path.exists(fixed_aes_key_path):
                    try:
                        fixed_aes_key = open(fixed_aes_key_path, "rb").read().strip()
                    except Exception:
                        fixed_aes_key = None
                    if fixed_aes_key is not None and len(fixed_aes_key) != 32:
                        fixed_aes_key = None

                aes_key = fixed_aes_key if fixed_aes_key is not None else get_random_bytes(32)
                iv = get_random_bytes(16)

                plaintext = b""
                if isinstance(req.get("plaintext"), str):
                    plaintext = req.get("plaintext").encode("utf-8")
                if not plaintext:
                    plaintext = _read_plaintext_from_disk()

                await ws.send_text(json.dumps({"type": "log", "message": "[+] Đang mã hóa AES-CBC..."}))
                ciphertext = aes256_cbc_encrypt(plaintext, aes_key, iv)

                # Hash per required formula
                hash_hex = packet_hash_sha512(iv, ciphertext, exp_iso)

                # RSA encrypt session key
                enc_session_key = rsa_encrypt_pkcs1v15(aes_key, receiver_public_key)

                # Sign metadata
                sender_private_key = rsa_load_private_key_pem(SENDER_PRIVATE_KEY_PATH)
                sig_raw = rsa_sign_metadata_sha512_pkcs1v15(metadata_bytes, sender_private_key)

                # Save artifacts for tamper testing + requested "folder"
                ensure_dir(ARTIFACTS_DIR)
                session_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                session_dir = os.path.join(ARTIFACTS_DIR, f"{session_id}")
                ensure_dir(session_dir)

                # Always store original values
                with open(os.path.join(session_dir, "aes_cipher.bin"), "wb") as f:
                    f.write(ciphertext)
                with open(os.path.join(session_dir, "aes_iv.bin"), "wb") as f:
                    f.write(iv)
                # Store enc_session_key bytes (what receiver uses to decrypt AES key)
                with open(os.path.join(session_dir, "enc_session_key.bin"), "wb") as f:
                    f.write(enc_session_key)

                # Store packet.json exactly
                ciphertext_to_send = ciphertext
                if packet_tamper_requested:
                    ciphertext_to_send = tamper_one_byte(ciphertext)

                packet = {
                    "type": "encrypted_packet",
                    "iv": b64e(iv),
                    "cipher": b64e(ciphertext_to_send),
                    "hash": hash_hex,
                    "sig": b64e(sig_raw),
                    "exp": exp_iso,
                    "enc_session_key": b64e(enc_session_key),
                    "filename": filename,
                }

                with open(os.path.join(session_dir, "packet.json"), "w", encoding="utf-8") as f:
                    json.dump(packet, f, ensure_ascii=False, indent=2)

                await ws.send_text(json.dumps({"type": "log", "message": "[+] Đang verify hash/chữ ký + ACK/NACK"}))
                await ws.send_text(json.dumps(packet))

    except WebSocketDisconnect:
        return

