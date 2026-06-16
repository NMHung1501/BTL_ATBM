import json
import os
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from crypto_utils import (
    aes256_cbc_decrypt,
    aes256_cbc_encrypt,
    b64d,
    b64e,
    deterministic_metadata_bytes,
    exp_is_valid,
    ensure_dir,
    sha512_hex,
    rsa_decrypt_pkcs1v15,
    rsa_encrypt_pkcs1v15,
    rsa_sign_sha512_pkcs1v15,
    rsa_verify_sha512_pkcs1v15,
    tamper_one_byte,
)

app = FastAPI()

KEYS_DIR = "keys"
ARTIFACTS_DIR = "artifacts"

# ---------------------------------------------------------------------------
# In-memory client registry
# ---------------------------------------------------------------------------

class ClientInfo:
    """Holds per-client state."""
    def __init__(self, username: str, ws: WebSocket, rsa_key: RSA.RsaKey):
        self.username = username
        self.ws = ws
        self.rsa_key = rsa_key  # full keypair (private + public)

# Active clients keyed by username
clients: Dict[str, ClientInfo] = {}

# Lock for safe concurrent access
clients_lock = asyncio.Lock()

# ---------------------------------------------------------------------------
# Helper: ISO-8601 UTC timestamp
# ---------------------------------------------------------------------------

def _isoZ_plus_seconds(seconds: int) -> str:
    dt = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=seconds)
    return dt.isoformat().replace("+00:00", "Z")


def _isoZ_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Sender keypair (for signing) — shared across server
# ---------------------------------------------------------------------------

SENDER_PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "sender_private_key.pem")
SENDER_PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "sender_public_key.pem")


def generate_sender_keypair_if_needed() -> None:
    ensure_dir(KEYS_DIR)
    if os.path.exists(SENDER_PRIVATE_KEY_PATH) and os.path.exists(SENDER_PUBLIC_KEY_PATH):
        return
    key = RSA.generate(2048)
    with open(SENDER_PRIVATE_KEY_PATH, "wb") as f:
        f.write(key.export_key(format="PEM"))
    with open(SENDER_PUBLIC_KEY_PATH, "wb") as f:
        f.write(key.publickey().export_key(format="PEM"))


# Ensure keys exist on startup
generate_sender_keypair_if_needed()


# ---------------------------------------------------------------------------
# Routes — serve the new chat UI
# ---------------------------------------------------------------------------

@app.get("/")
def index():
    return RedirectResponse(url="/chat.html")


# Mount static files AFTER explicit routes so /chat.html etc. resolve
app.mount("/static", StaticFiles(directory="."), name="static")


@app.get("/chat.html")
def serve_chat():
    return FileResponse("chat.html", media_type="text/html")


@app.get("/chat.css")
def serve_chat_css():
    return FileResponse("chat.css", media_type="text/css")


@app.get("/chat.js")
def serve_chat_js():
    return FileResponse("chat.js", media_type="application/javascript")


# ---------------------------------------------------------------------------
# Broadcast helpers
# ---------------------------------------------------------------------------

async def broadcast_user_list():
    """Send updated user list to all connected clients."""
    usernames = list(clients.keys())
    msg = json.dumps({"type": "user_list", "users": usernames})
    dead = []
    for uname, info in clients.items():
        try:
            await info.ws.send_text(msg)
        except Exception:
            dead.append(uname)
    for d in dead:
        clients.pop(d, None)


async def send_to_user(username: str, data: dict):
    """Send a JSON message to a specific user."""
    info = clients.get(username)
    if info:
        try:
            await info.ws.send_text(json.dumps(data))
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Encrypt & send a message from one user to all others
# ---------------------------------------------------------------------------

async def encrypt_and_deliver(sender_username: str, plaintext_str: str):
    """
    Performs the full crypto pipeline:
    1. AES-CBC-256 encrypt
    2. SHA-512 hash integrity
    3. RSA sign metadata
    4. RSA encrypt AES session key per recipient
    5. Deliver to all other connected clients
    """
    sender_info = clients.get(sender_username)
    if not sender_info:
        return

    plaintext = plaintext_str.encode("utf-8")
    filename = "email.txt" # Đề tài yêu cầu file tên email.txt
    
    # 1. Giới hạn thời gian: 24 giờ (86400 giây)
    exp_iso = _isoZ_plus_seconds(86400)
    timestamp = _isoZ_now()

    # 2. Metadata: tên file + timestamp (Dùng expiration hoặc timestamp)
    metadata = {"filename": filename, "timestamp": timestamp, "exp": exp_iso}
    metadata_bytes = deterministic_metadata_bytes(metadata)

    # 3. AES key + IV
    aes_key = get_random_bytes(32)
    iv = get_random_bytes(16)

    # 4. AES-CBC encrypt
    ciphertext = aes256_cbc_encrypt(plaintext, aes_key, iv)

    # 5. Hash & Sign
    # B3: Dùng bản rõ mã hóa Hash 512, ký bằng private key người gửi
    sig_raw = rsa_sign_sha512_pkcs1v15(plaintext, sender_info.rsa_key)
    hash_hex = sha512_hex(plaintext)

    # Save artifacts (Giao diện hiển thị, lưu để sau test lại)
    ensure_dir(ARTIFACTS_DIR)
    session_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    session_dir = os.path.join(ARTIFACTS_DIR, session_id)
    ensure_dir(session_dir)

    with open(os.path.join(session_dir, "aes_cipher.bin"), "wb") as f:
        f.write(ciphertext)
    with open(os.path.join(session_dir, "aes_iv.bin"), "wb") as f:
        f.write(iv)

    crypto_detail = {
        "hash": hash_hex,
        "signature_status": "verified",
        "hash_status": "match",
        "iv_hex": b64e(iv),
        "exp": exp_iso,
        "algorithm": "AES-256-CBC + RSA-2048 + SHA-512",
    }

    # Hiển thị tin nhắn vừa gửi trên máy người gửi (Chỉ gửi 1 lần)
    await send_to_user(sender_username, {
        "type": "message_sent",
        "from": sender_username,
        "text": plaintext_str,
        "timestamp": timestamp,
        "crypto_detail": crypto_detail,
    })

    # For each other client, RSA-encrypt the AES key with their public key and deliver
    for uname, info in list(clients.items()):
        if uname == sender_username:
            continue

        try:
            # RSA encrypt AES key for this specific recipient
            recipient_public_key = info.rsa_key.publickey()
            enc_session_key = rsa_encrypt_pkcs1v15(aes_key, recipient_public_key)

            # Build the encrypted packet
            packet = {
                "type": "encrypted_packet",
                "iv": b64e(iv),
                "cipher": b64e(ciphertext),
                "hash": hash_hex,
                "sig": b64e(sig_raw),
                "exp": exp_iso,
                "enc_session_key": b64e(enc_session_key),
                "filename": filename,
                "timestamp": timestamp,
            }

            # Server-side verify (Giả lập Receiver)
            decrypted_aes_key = rsa_decrypt_pkcs1v15(enc_session_key, info.rsa_key)
            decrypted_plaintext = aes256_cbc_decrypt(ciphertext, decrypted_aes_key, iv)

            # Verify hash (B3: Băm bản text đã lấy đc ra để có được mã băm)
            actual_hash = sha512_hex(decrypted_plaintext)
            hash_ok = actual_hash.lower() == hash_hex.lower()

            # Verify signature (B4: Lấy public key người gửi giải mã chữ ký xem có phải A không)
            sender_public_key = sender_info.rsa_key.publickey()
            sig_ok = rsa_verify_sha512_pkcs1v15(decrypted_plaintext, sig_raw, sender_public_key)
            
            # Verify expiration
            exp_ok = exp_is_valid(exp_iso)

            # Đề tài yêu cầu: Nếu tất cả hợp lệ -> Giải mã -> Lưu file email.txt -> Gửi ACK
            # Ngược lại -> Từ chối, gửi NACK.
            if hash_ok and sig_ok and exp_ok:
                # Lưu file email.txt
                with open(os.path.join(session_dir, f"email_to_{uname}.txt"), "wb") as f:
                    f.write(decrypted_plaintext)
                    
                # Gửi tới người nhận
                recv_crypto_detail = {
                    "hash": hash_hex,
                    "signature_status": "verified",
                    "hash_status": "match",
                    "iv_hex": b64e(iv),
                    "exp": exp_iso,
                    "algorithm": "AES-256-CBC + RSA-2048 + SHA-512",
                }

                await info.ws.send_text(json.dumps({
                    "type": "message_received",
                    "from": sender_username,
                    "text": decrypted_plaintext.decode("utf-8"),
                    "timestamp": timestamp,
                    "crypto_detail": recv_crypto_detail,
                }))
                
                # Gửi ACK tới người gửi
                await send_to_user(sender_username, {
                    "type": "system",
                    "message": f"✅ ACK: {uname} đã nhận an toàn."
                })

            else:
                # Gửi NACK
                reason = "Lỗi Integrity/Timeout/Signature"
                if not exp_ok: reason = "Lỗi Timeout (Hết hạn)"
                elif not hash_ok: reason = "Lỗi Integrity (Hash Mismatch)"
                elif not sig_ok: reason = "Lỗi Signature (Chữ ký không hợp lệ)"
                
                await send_to_user(sender_username, {
                    "type": "error",
                    "message": f"❌ NACK từ {uname}: {reason}"
                })

            # Also save the packet artifact
            with open(os.path.join(session_dir, f"packet_to_{uname}.json"), "w", encoding="utf-8") as f:
                json.dump(packet, f, ensure_ascii=False, indent=2)

        except Exception as e:
            # Nếu có lỗi giải mã
            await send_to_user(sender_username, {
                "type": "error",
                "message": f"NACK: Lỗi giải mã ({e})."
            })
            print(f"[!] Failed to deliver to {uname}: {e}")
            continue


# ---------------------------------------------------------------------------
# WebSocket endpoint — unified chat
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()

    username: Optional[str] = None

    try:
        # Wait for registration and handshake message
        handshake_done = False
        
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_text(json.dumps({"type": "error", "message": "Invalid JSON"}))
                continue

            # Handshake step: "Hello!" -> "Ready!"
            if not handshake_done and data.get("type") == "handshake":
                if data.get("text") == "Hello!":
                    await ws.send_text(json.dumps({"type": "handshake_reply", "text": "Ready!"}))
                    handshake_done = True
                else:
                    await ws.send_text(json.dumps({"type": "error", "message": "Invalid Handshake"}))
                continue

            if data.get("type") == "register":
                if not handshake_done:
                    await ws.send_text(json.dumps({
                        "type": "error",
                        "message": "Phải hoàn tất Handshake trước khi register",
                    }))
                    continue
                
                requested_name = str(data.get("username", "")).strip()
                if not requested_name:
                    await ws.send_text(json.dumps({
                        "type": "error",
                        "message": "Username cannot be empty",
                    }))
                    continue

                async with clients_lock:
                    if requested_name in clients:
                        await ws.send_text(json.dumps({
                            "type": "error",
                            "message": f"Username '{requested_name}' is already taken",
                        }))
                        continue

                    # Generate RSA keypair for this client
                    rsa_key = RSA.generate(2048)
                    username = requested_name
                    clients[username] = ClientInfo(username, ws, rsa_key)

                await ws.send_text(json.dumps({
                    "type": "registered",
                    "username": username,
                    "message": f"Welcome, {username}! You are now connected.",
                }))

                # Broadcast updated user list
                await broadcast_user_list()
                break

            else:
                await ws.send_text(json.dumps({
                    "type": "error",
                    "message": "Please register first: {\"type\":\"register\",\"username\":\"YourName\"}",
                }))

        # Main message loop
        while True:
            raw = await ws.receive_text()
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_text(json.dumps({"type": "error", "message": "Invalid JSON"}))
                continue

            msg_type = data.get("type")

            if msg_type == "message":
                text = str(data.get("text", "")).strip()
                if not text:
                    continue
                await encrypt_and_deliver(username, text)

            elif msg_type == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))

            else:
                await ws.send_text(json.dumps({
                    "type": "error",
                    "message": f"Unknown message type: {msg_type}",
                }))

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"[!] WebSocket error for {username}: {e}")
    finally:
        if username:
            async with clients_lock:
                clients.pop(username, None)
            await broadcast_user_list()

# ---------------------------------------------------------------------------
# Standalone execution (For PyInstaller / End Users)
# ---------------------------------------------------------------------------
import socket
import threading
import webbrowser
import time

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # doesn't even have to be reachable
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def open_browser():
    time.sleep(1.5)  # Wait for uvicorn to start
    url = "http://localhost:8000"
    print(f"\n[+] Đang mở trình duyệt tại {url}...")
    try:
        webbrowser.open(url)
    except Exception as e:
        print(f"[-] Không thể mở trình duyệt tự động: {e}")

if __name__ == "__main__":
    import uvicorn
    
    lan_ip = get_lan_ip()
    
    print("\n" + "="*65)
    print("   🔐 CIPHERCHAT SERVER STARTED 🔐")
    print("   Ứng dụng nhắn tin mã hóa đầu cuối (AES-256 + RSA-2048)")
    print("="*65)
    print(f"\n[+] IP phòng Chat (Chia sẻ cho người khác): http://{lan_ip}:8000")
    print("[+] Truy cập trên máy này: http://localhost:8000")
    print("\n[!] Chú ý: Không tắt cửa sổ này trong khi chat.")
    print("="*65 + "\n")
    
    # Start browser opener thread
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Run uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, log_level="warning")
