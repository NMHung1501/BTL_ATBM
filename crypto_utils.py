import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def iso_utc_now() -> str:
    # ISO-8601 with Z suffix
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def add_seconds_iso(exp_base_iso: str, seconds: int) -> str:
    # exp_base_iso format like ...Z
    dt = datetime.fromisoformat(exp_base_iso.replace("Z", "+00:00"))
    dt = dt + __import__("datetime").timedelta(seconds=seconds)
    return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def exp_is_valid(exp_iso: str) -> bool:
    dt = datetime.fromisoformat(exp_iso.replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    # The expiration time is already calculated and passed as exp_iso
    return now <= dt


def sha512_hex(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()



def deterministic_metadata_bytes(metadata: dict) -> bytes:
    # Deterministic JSON: sort_keys + compact separators
    text = json.dumps(metadata, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


def rsa_load_private_key_pem(path: str) -> RSA.RsaKey:
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_load_public_key_pem(path: str) -> RSA.RsaKey:
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def rsa_sign_sha512_pkcs1v15(message_bytes: bytes, private_key: RSA.RsaKey) -> bytes:
    h = SHA512.new(message_bytes)
    signer = pkcs1_15.new(private_key)
    return signer.sign(h)


def rsa_verify_sha512_pkcs1v15(message_bytes: bytes, signature: bytes, public_key: RSA.RsaKey) -> bool:
    h = SHA512.new(message_bytes)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def rsa_sign_metadata_sha512_pkcs1v15(metadata_bytes: bytes, sender_private_key: RSA.RsaKey) -> bytes:
    # Backward-compatible wrapper
    return rsa_sign_sha512_pkcs1v15(metadata_bytes, sender_private_key)



def rsa_verify_metadata_sha512_pkcs1v15(metadata_bytes: bytes, signature: bytes, sender_public_key: RSA.RsaKey) -> bool:
    h = SHA512.new(metadata_bytes)
    verifier = pkcs1_15.new(sender_public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def rsa_encrypt_pkcs1v15(session_key: bytes, receiver_public_key: RSA.RsaKey) -> bytes:
    # RSA encryption with PKCS#1 v1.5 padding
    # Use Crypto.Cipher.PKCS1_v1_5 is typical, but RSA key encryption in pycryptodome uses PKCS#1 v1.5 via PKCS1_v1_5.
    from Crypto.Cipher import PKCS1_v1_5

    cipher = PKCS1_v1_5.new(receiver_public_key)
    return cipher.encrypt(session_key)


def rsa_decrypt_pkcs1v15(enc_session_key: bytes, receiver_private_key: RSA.RsaKey) -> bytes:
    from Crypto.Cipher import PKCS1_v1_5

    cipher = PKCS1_v1_5.new(receiver_private_key)
    sentinel = b"__decrypt_failed__"
    dec = cipher.decrypt(enc_session_key, sentinel)
    if dec == sentinel:
        raise ValueError("RSA decryption failed")
    return dec


def aes256_cbc_encrypt(plaintext: bytes, key_32: bytes, iv: bytes) -> bytes:
    if len(key_32) != 32:
        raise ValueError("AES key must be 32 bytes")
    if len(iv) != 16:
        raise ValueError("AES-CBC IV must be 16 bytes")

    # PKCS#7 padding
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len]) * pad_len

    cipher = AES.new(key_32, AES.MODE_CBC, iv=iv)
    return cipher.encrypt(padded)


def aes256_cbc_decrypt(ciphertext: bytes, key_32: bytes, iv: bytes) -> bytes:
    if len(key_32) != 32:
        raise ValueError("AES key must be 32 bytes")
    if len(iv) != 16:
        raise ValueError("AES-CBC IV must be 16 bytes")

    cipher = AES.new(key_32, AES.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ciphertext)

    if not padded:
        raise ValueError("Empty plaintext")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS#7 padding")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    return padded[:-pad_len]


def packet_hash_sha512(iv: bytes, ciphertext: bytes, exp_iso: str) -> str:
    # Required: SHA-512(IV || ciphertext || expiration)
    return sha512_hex(iv + ciphertext + exp_iso.encode("utf-8"))


def tamper_one_byte(ciphertext: bytes) -> bytes:
    if not ciphertext:
        raise ValueError("ciphertext empty")
    i = get_random_bytes(1)[0] % len(ciphertext)
    b = ciphertext[i]
    # flip one bit deterministically-ish
    flipped = b ^ 0x01
    return ciphertext[:i] + bytes([flipped]) + ciphertext[i + 1 :]


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

