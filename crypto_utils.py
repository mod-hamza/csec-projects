# crypto_utils.py — Caesar and AES helpers
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def caesar(text, shift):
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return ''.join(out)

def aes_enc(text, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(text.encode(), 16))
    return base64.b64encode(iv + ct).decode()

def aes_dec(b64, key):
    raw = base64.b64decode(b64)
    cipher = AES.new(key, AES.MODE_CBC, raw[:16])
    return unpad(cipher.decrypt(raw[16:]), 16).decode()
