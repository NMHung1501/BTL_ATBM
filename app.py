import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from Crypto.PublicKey import RSA

from crypto_utils import (
    rsa_generate_keypair_2048,
    rsa_encrypt_pkcs1_v1_5,
    rsa_decrypt_pkcs1_v1_5,
    rsa_sign_sha512,
    rsa_verify_sha512,
    aes_encrypt_cbc,
    aes_decrypt_cbc,
    generate_iv,
    sha512_hex,
    b64e,
    b64d,
)


app = FastAPI()

# ===== dirs =====
ROOT_DIR = Path(__file__).resolve().parent
KEY_DIR = ROOT_DIR / "keys"
ARTIFACT_DIR = ROOT_DIR / "artifacts"

KEY_DIR.mkdir(parents=True, exist_ok=True)
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

# key files for imports/exports (for lab/debug; each transfer uses freshly generated keys by default)
SENDER_PRIVATE_PEM = KEY_DIR / "sender_private.pem"
SENDER_PUBLIC_PEM = KEY_DIR / "sender_public.pem"
RECEIVER_PRIVATE_PEM = KEY_DIR / "receiver_private.pem"
RECEIVER_PUBLIC_PEM = KEY_DIR / "receiver_public.pem"

# artifacts latest_* (what you edit manually to tamper)
ART_LATEST_PACKET_JSON = ARTIFACT_DIR / "latest_packet.json"
ART_LATEST_CIPHERTEXT_BIN = ARTIFACT_DIR / "latest_ciphertext.bin"  # AES-CBC ciphertext
ART_LATEST_IV_BIN = ARTIFACT_DIR / "latest_iv.bin"
ART_LATEST_ENC_SESSIONKEY_BIN = ARTIFACT_DIR / "latest_enc_session_key.bin"  # RSA encrypted AES key
ART_LATEST_ENC_HASH_BIN = ARTIFACT_DIR / "latest_signature.bin"  # RSA encrypted hash of plaintext (lab naming)
ART_LATEST_HASH_PLAINTEXT_TXT = ARTIFACT_DIR / "latest_hash_plaintext.txt"  # hex string
ART_LATEST_EXP_TXT = ARTIFACT_DIR / "latest_exp.txt"
ART_LATEST_FILENAME_TXT = ARTIFACT_DIR / "latest_filename.txt"


# simplistic per-connection state
receivers: Dict[str, Dict[str, Any]] = {}


@app.get("/")
def index():
    return HTMLResponse(
        "Frontend nằm ở index.html. Hãy mở index.html trên trình duyệt hoặc serve static thông qua server."
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso8601(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def build_metadata_bytes(filename: str, exp_iso: str) -> bytes:
    meta = {"filename": filename, "timestamp": exp_iso}
    return json.dumps(meta, separators=(",", ":"), sort_keys=True).encode("utf-8")


def ensure_bytes_len_for_aes_key(key: bytes) -> bytes:
    # AES CBC requires 16/24/32 bytes. We use 32.
    if len(key) in (16, 24, 32):
        return key
    raise ValueError(f"Invalid AES key length: {len(key)}")


def write_artifacts_for_transfer(
    *,
    filename: str,
    exp_iso: str,
    iv: bytes,
    ciphertext: bytes,
    enc_session_key: bytes,
    enc_hash_plaintext: bytes,
    packet: Dict[str, Any],
) -> None:
    # write editable files for tampering
    ART_LATEST_FILENAME_TXT.write_text(filename, encoding="utf-8")
    ART_LATEST_EXP_TXT.write_text(exp_iso, encoding="utf-8")
    ART_LATEST_IV_BIN.write_bytes(iv)
    ART_LATEST_CIPHERTEXT_BIN.write_bytes(ciphertext)
    ART_LATEST_ENC_SESSIONKEY_BIN.write_bytes(enc_session_key)
    ART_LATEST_ENC_HASH_BIN.write_bytes(enc_hash_plaintext)
    ART_LATEST_HASH_PLAINTEXT_TXT.write_text(packet["hash_plaintext_hex"], encoding="utf-8")

    # full json payload
    ART_LATEST_PACKET_JSON.write_text(json.dumps(packet, indent=2), encoding="utf-8")


def load_rsa_keypair_from_pem(pem_path: Path) -> RSA.RsaKey:
    if not pem_path.exists():
        raise FileNotFoundError(str(pem_path))
    return RSA.import_key(pem_path.read_bytes())


def rsa_encrypt_raw_private_like(hash_bytes_hex: str, sender_private: RSA.RsaKey) -> bytes:
    """
    We need: encrypt the hex-string hash (plaintext hash) with RSA private key.

    Requirement you gave: "bản text băm xong => mã hash . lấy mã hash đó + private key để mã hóa đoạn hash đó".

    PyCryptodome RSA raw private 'encryption' is equivalent to RSA sign operation.
    We implement signing of the hash bytes directly using PKCS#1 v1.5/SHA-512.

    But you want RSA over the already computed hash value.
    To keep deterministic and verifiable, we sign SHA-512 of the ASCII hash_hex string.

    Then receiver verifies by verifying RSA signature of the same message.

    However your described test compares hashes after decrypt AES.
    We will follow your logic exactly by defining:
      - plaintext_hash_hex = SHA512(plaintext) as hex.
      - sig = RSA_sign_SHA512(plaintext_hash_hex_bytes, sender_private)
      - receiver validates by RSA_verify_SHA512(plaintext_hash_hex_bytes, sig, sender_public)

    This is consistent with RSA+SHA-512 requirement and uses PKCS#1 v1.5.
    """
    # We reuse rsa_sign_sha512 / rsa_verify_sha512 helpers.
    msg = hash_bytes_hex.encode("utf-8")
    return rsa_sign_sha512(msg, sender_private)


def rsa_verify_raw_private_like(hash_bytes_hex: str, signature: bytes, sender_public: RSA.RsaKey) -> bool:
    msg = hash_bytes_hex.encode("utf-8")
    return rsa_verify_sha512(msg, signature, sender_public)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    role: Optional[str] = None

    try:
        # Step 1: Handshake
        hello = await ws.receive_text()
        if hello == "Hello!":
            role = "sender"
        elif hello == "Receiver!":
            role = "receiver"
        else:
            await ws.send_text("Unknown!")
            await ws.close()
            return

        await ws.send_text("Ready!")

        # Step 2-4 follow
        if role == "receiver":
            # receiver creates RSA keypair
            receiver_priv, receiver_pub = rsa_generate_keypair_2048()
            receivers[str(id(ws))] = {
                "private": receiver_priv,
                "public": receiver_pub,
            }
            await ws.send_text(
                json.dumps(
                    {
                        "type": "public_key",
                        "public_key_pem": receiver_pub.export_key().decode("utf-8"),
                    }
                )
            )

            # wait for sender payload
            payload_text = await ws.receive_text()
            payload = json.loads(payload_text)

            # payload contains:
            # {
            #   filename, exp,
            #   iv (b64), ciphertext (b64),
            #   enc_session_key (b64),
            #   enc_hash_plaintext (b64)  (called sig in payload for UI)
            #   sender_public_key_pem
            # }
            filename = payload.get("filename", "email.txt")
            exp_iso = payload["exp"]

            # timeout check (24h validity)
            exp_dt = parse_iso8601(exp_iso)
            if utc_now() > exp_dt:
                await ws.send_text(json.dumps({"type": "NACK", "reason": "Timeout/Expired"}))
                return

            iv = b64d(payload["iv"])
            ciphertext = b64d(payload["ciphertext"])
            enc_session_key = b64d(payload["enc_session_key"])
            enc_hash_plaintext = b64d(payload["enc_hash_plaintext"])
            sender_pub_pem = payload["sender_public_key_pem"]
            sender_pub = RSA.import_key(sender_pub_pem)

            # decrypt session key
            receiver_priv = receivers[str(id(ws))]["private"]
            session_key = rsa_decrypt_pkcs1_v1_5(receiver_priv, enc_session_key)
            try:
                session_key = ensure_bytes_len_for_aes_key(session_key)
            except Exception:
                await ws.send_text(json.dumps({"type": "NACK", "reason": "Session Key invalid"}))
                return

            # decrypt file
            try:
                plaintext = aes_decrypt_cbc(session_key, iv, ciphertext)
            except Exception:
                await ws.send_text(json.dumps({"type": "NACK", "reason": "AES Decrypt Failed"}))
                return

            # compute plaintext hash
            plaintext_hash_hex = sha512_hex(iv, ciphertext, exp_iso)
            # NOTE: sha512_hex in crypto_utils is SHA512(IV||cipher||exp)
            # For your updated requirement, plaintext hash should be SHA-512(plaintext bytes).
            # crypto_utils lacks helper for SHA512(plaintext). We'll compute inline via RSA verify.
            # We MUST recompute properly:
            from Crypto.Hash import SHA512

            h = SHA512.new(plaintext)
            plaintext_hash_hex = h.hexdigest()

            # verify signature (RSA over hash_hex string) using sender public key
            sig_ok = rsa_verify_raw_private_like(plaintext_hash_hex, enc_hash_plaintext, sender_pub)
            if not sig_ok:
                await ws.send_text(json.dumps({"type": "NACK", "reason": "Integrity/Signature mismatch"}))
                return

            # additionally compute SHA512(IV||cipher||exp) only for debug logging
            _hash_debug = sha512_hex(iv, ciphertext, exp_iso)

            # Save file
            out_name = "email.txt"
            with open(out_name, "wb") as f:
                f.write(plaintext)

            await ws.send_text(json.dumps({"type": "ACK", "status": "Success", "saved_as": out_name}))
            return

        else:
            # sender role
            # receive receiver public key already sent by receiver
            receiver_pub_text = await ws.receive_text()
            receiver_pub_msg = json.loads(receiver_pub_text)
            receiver_pub = RSA.import_key(receiver_pub_msg["public_key_pem"])

            # receive user plaintext package from UI
            req_text = await ws.receive_text()
            req = json.loads(req_text)

            filename = req.get("filename", "email.txt")
            exp_iso = req.get("exp")
            if not exp_iso:
                exp_iso = (utc_now() + timedelta(hours=24)).replace(microsecond=0).isoformat()

            plaintext_b64 = req["plaintext_b64"]
            plaintext = b64d(plaintext_b64)

            # receiver public key encryption session key (RSA PKCS#1 v1.5)
            session_key = os.urandom(32)
            session_key = ensure_bytes_len_for_aes_key(session_key)
            enc_session_key = rsa_encrypt_pkcs1_v1_5(receiver_pub, session_key)

            # AES-CBC encrypt
            iv = generate_iv()
            ciphertext = aes_encrypt_cbc(session_key, iv, plaintext)

            # hash plaintext (SHA-512(plaintext)) => hex string
            from Crypto.Hash import SHA512

            h = SHA512.new(plaintext)
            plaintext_hash_hex = h.hexdigest()

            # signature: RSA private over hash_hex string (PKCS#1 v1.5 + SHA-512)
            sender_priv, sender_pub = rsa_generate_keypair_2048()
            sig = rsa_encrypt_raw_private_like(plaintext_hash_hex, sender_priv)

            payload = {
                "type": "encrypted_package_v2",
                "filename": filename,
                "exp": exp_iso,
                "iv": b64e(iv),
                "ciphertext": b64e(ciphertext),
                "enc_session_key": b64e(enc_session_key),
                "enc_hash_plaintext": b64e(sig),
                "sender_public_key_pem": sender_pub.export_key().decode("utf-8"),
                # debug extra fields
                "hash_plaintext_hex": plaintext_hash_hex,
            }

            # write artifacts for manual tamper
            write_artifacts_for_transfer(
                filename=filename,
                exp_iso=exp_iso,
                iv=iv,
                ciphertext=ciphertext,
                enc_session_key=enc_session_key,
                enc_hash_plaintext=sig,
                packet=payload,
            )

            await ws.send_text(json.dumps(payload))

            # ACK/NACK
            ack = await ws.receive_text()
            await ws.send_text(ack)
            return

    except WebSocketDisconnect:
        return
    except Exception as e:
        try:
            await ws.send_text(json.dumps({"type": "NACK", "reason": f"Server error: {e}"}))
        except Exception:
            pass
        return

