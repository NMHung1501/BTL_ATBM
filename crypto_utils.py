import base64
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def generate_iv(block_size: int = 16) -> bytes:
    return get_random_bytes(block_size)


def aes_encrypt_cbc(aes_key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return ct


def aes_decrypt_cbc(aes_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    pt = cipher.decrypt(ciphertext)
    return unpad(pt, AES.block_size)


def rsa_generate_keypair_2048():
    key = RSA.generate(2048)
    return key, key.publickey()


def rsa_encrypt_pkcs1_v1_5(public_key: RSA.RsaKey, message: bytes) -> bytes:
    cipher = PKCS1_v1_5.new(public_key)
    # Bắt buộc theo PKCS#1 v1.5 padding
    return cipher.encrypt(message)


def rsa_decrypt_pkcs1_v1_5(private_key: RSA.RsaKey, ciphertext: bytes) -> bytes:
    cipher = PKCS1_v1_5.new(private_key)
    sentinel = b"__invalid__"
    return cipher.decrypt(ciphertext, sentinel=sentinel)


def rsa_sign_sha512(message: bytes, private_key: RSA.RsaKey) -> bytes:
    h = SHA512.new(message)
    signer = pkcs1_15.new(private_key)
    return signer.sign(h)


def rsa_verify_sha512(message: bytes, signature: bytes, public_key: RSA.RsaKey) -> bool:
    h = SHA512.new(message)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def sha512_hex(iv: bytes, ciphertext: bytes, exp_iso: str) -> str:
    # hash = SHA-512(IV || ciphertext || expiration)
    h = SHA512.new()
    h.update(iv)
    h.update(ciphertext)
    h.update(exp_iso.encode("utf-8"))
    return h.hexdigest()


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

