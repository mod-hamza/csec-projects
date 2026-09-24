# hamza_server.py — full setup phase including EC packet
import socket, threading, base64, subprocess
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

HOST = '0.0.0.0'
PORT = 9090

def send_pkt(conn, *parts):
    conn.sendall(('|'.join(str(p) for p in parts) + '\n').encode())

def recv_pkt(conn):
    buf = b''
    while not buf.endswith(b'\n'):
        chunk = conn.recv(4096)
        if not chunk: return []
        buf += chunk
    return buf.decode().strip().split('|')

def caesar(text, shift):
    out = []
    for ch in text:
        if ch.isalpha():
            b = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - b + shift) % 26 + b))
        else: out.append(ch)
    return ''.join(out)

def aes_enc(text, key):
    iv = get_random_bytes(16)
    c = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + c.encrypt(pad(text.encode(), 16))).decode()

def aes_dec(b64, key):
    raw = base64.b64decode(b64)
    c = AES.new(key, AES.MODE_CBC, raw[:16])
    return unpad(c.decrypt(raw[16:]), 16).decode()

class Session:
    def __init__(self):
        self.secured = False; self.algo = None
        self.key = None; self.rsa = None; self.wfile = None

def enc(text, s):
    if not s.secured: return text
    return aes_enc(text, s.key) if s.algo == 'AES' else caesar(text, s.key)

def dec(text, s):
    if not s.secured: return text
    return aes_dec(text, s.key) if s.algo == 'AES' else caesar(text, -s.key)

def setup(conn, s):
    pkt = recv_pkt(conn)
    if not pkt or pkt[0] != 'SS':
        send_pkt(conn, 'EE', 'E001', 'expected SS'); return False
    secure = (pkt[3].strip() == '1') if len(pkt) > 3 else False
    s.rsa = RSA.generate(2048)
    if not secure:
        send_pkt(conn, 'CC'); return True
    pub_b64 = base64.b64encode(s.rsa.publickey().export_key()).decode()
    send_pkt(conn, 'CC', pub_b64)
    pkt = recv_pkt(conn)
    if not pkt or pkt[0] != 'EC':
        send_pkt(conn, 'EE', 'E001', 'expected EC'); return False
    algo = pkt[1].strip().upper()
    raw = PKCS1_OAEP.new(s.rsa).decrypt(base64.b64decode(pkt[2].strip()))
    s.secured = True; s.algo = algo
    s.key = raw if algo == 'AES' else int(raw.decode().strip())
    return True

def handle_client(conn, addr):
    print(f'connected: {addr}')
    s = Session()
    try:
        setup(conn, s)
    except Exception as e: print(e)
    finally: conn.close()

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT)); srv.listen(10)
    print(f'listening on {PORT}')
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__': main()
