# hamza_server.py
# RFMP Server - Spring 2026
# Group: Hamza (415001013), Akour (433002101), Kawtar (433006015), Aya (433000484)
#
# How it works:
#   1. Client connects and sends a start packet (SS)
#   2. Server replies with CC. If secure mode, they exchange keys first.
#   3. Client sends commands (CM), server runs them and replies.
#   4. Client sends END when done.

import socket
import threading
import subprocess
import base64

# pycryptodome handles our RSA, AES crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

HOST = '0.0.0.0'
PORT = 9090


# ── tiny helpers ────────────────────────────────────────────────────────────

def send_pkt(conn, *parts):
    # packets are pipe-separated, newline-terminated  e.g. "SC|done\n"
    msg = '|'.join(str(p) for p in parts) + '\n'
    conn.sendall(msg.encode())

def recv_pkt(conn):
    # read until we hit the newline, then split on pipes
    buf = b''
    while not buf.endswith(b'\n'):  # keep reading until full packet arrives
        chunk = conn.recv(4096)
        if not chunk:
            return []
        buf += chunk
    return buf.decode().strip().split('|')


# ── Caesar cipher ───────────────────────────────────────────────────────────
# Basic letter-shift cipher. Shift 13 = ROT13 (its own inverse).

def caesar(text, shift):
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return ''.join(out)


# ── AES cipher ──────────────────────────────────────────────────────────────
# AES-CBC: we generate a fresh random IV for every message and prepend it
# to the ciphertext so the receiver can decrypt it.

def aes_enc(text, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(text.encode(), 16))
    return base64.b64encode(iv + ct).decode()

def aes_dec(b64, key):
    raw = base64.b64decode(b64)
    cipher = AES.new(key, AES.MODE_CBC, raw[:16])
    return unpad(cipher.decrypt(raw[16:]), 16).decode()


# ── per-client session state ─────────────────────────────────────────────────

class Session:
    def __init__(self):
        self.secured = False
        self.algo = None        # 'AES' or 'CAESAR'
        self.key = None         # bytes for AES, int for Caesar
        self.rsa = None         # server RSA key
        self.wfile = None       # open file handle during openWrite


def enc(text, s):
    if not s.secured:
        return text
    if s.algo == 'AES':
        return aes_enc(text, s.key)
    return caesar(text, s.key)

def dec(text, s):
    if not s.secured:
        return text
    if s.algo == 'AES':
        return aes_dec(text, s.key)
    return caesar(text, -s.key)


# ── setup phase ─────────────────────────────────────────────────────────────
# Handles the SS -> CC -> (EC) handshake at the start of every connection.

def setup(conn, s):
    pkt = recv_pkt(conn)

    # expect: SS | RFMP | v1.0 | 0-or-1
    if not pkt or pkt[0] != 'SS':
        send_pkt(conn, 'EE', 'E001', 'expected SS packet')
        return False

    secure = (pkt[3].strip() == '1') if len(pkt) > 3 else False

    # generate RSA key pair for this session
    s.rsa = RSA.generate(2048)

    if not secure:
        send_pkt(conn, 'CC')
        return True

    # send CC with our public key so client can encrypt the session key
    pub_b64 = base64.b64encode(s.rsa.publickey().export_key()).decode()
    send_pkt(conn, 'CC', pub_b64)

    # wait for the EC (encryption) packet from client
    pkt = recv_pkt(conn)
    if not pkt or pkt[0] != 'EC':
        send_pkt(conn, 'EE', 'E001', 'expected EC packet')
        return False

    # EC | ALGO | encrypted_session_key | username:client_pubkey
    algo = pkt[1].strip().upper()
    enc_key = base64.b64decode(pkt[2].strip())

    # decrypt the session key using our RSA private key
    raw = PKCS1_OAEP.new(s.rsa).decrypt(enc_key)

    s.secured = True
    s.algo = algo
    s.key = raw if algo == 'AES' else int(raw.decode().strip())
    return True


# ── operation phase ──────────────────────────────────────────────────────────

def handle_prompt(conn, cmd, s):
    # run the shell command, send back its output
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        out = (result.stdout + result.stderr).strip() or '(no output)'
        send_pkt(conn, 'SC', enc(out, s))
    except Exception as e:
        send_pkt(conn, 'EE', 'E004', str(e))

def handle_openread(conn, filename, s):
    try:
        content = open(filename).read()
        send_pkt(conn, 'DP', enc(content, s))
    except FileNotFoundError:
        send_pkt(conn, 'EE', 'E002', 'file not found')
    except PermissionError:
        send_pkt(conn, 'EE', 'E003', 'permission denied')

def handle_openwrite(conn, filename, s):
    try:
        s.wfile = open(filename, 'w')
        send_pkt(conn, 'SC', f'ready to write {filename}')
    except PermissionError:
        send_pkt(conn, 'EE', 'E003', 'permission denied')

def handle_dp(conn, data, s):
    # data packet — write decrypted content to the open file
    if s.wfile is None:
        send_pkt(conn, 'EE', 'E004', 'no file open for writing')
        return
    try:
        s.wfile.write(dec(data, s))
        s.wfile.flush()
        send_pkt(conn, 'SC', 'data written')
    except Exception as e:
        send_pkt(conn, 'EE', 'E004', str(e))

def operate(conn, s):
    while True:
        pkt = recv_pkt(conn)
        if not pkt:
            break

        ptype = pkt[0].strip().upper()

        if ptype == 'END':
            if s.wfile:
                s.wfile.close()
                s.wfile = None
            send_pkt(conn, 'SC', 'session closed')
            break

        if ptype == 'DP':
            handle_dp(conn, pkt[1] if len(pkt) > 1 else '', s)
            continue

        if ptype != 'CM' or len(pkt) < 3:
            send_pkt(conn, 'EE', 'E001', 'malformed packet')
            continue

        cmd_type = pkt[1].strip().lower()
        args = pkt[2] if len(pkt) > 2 else ''

        if cmd_type == 'prompt':
            handle_prompt(conn, args, s)
        elif cmd_type == 'openread':
            handle_openread(conn, args, s)
        elif cmd_type == 'openwrite':
            handle_openwrite(conn, args, s)
        else:
            send_pkt(conn, 'EE', 'E001', 'unknown command')


# ── thread entry point ───────────────────────────────────────────────────────

def handle_client(conn, addr):
    print(f'connected: {addr}')
    s = Session()
    try:
        if setup(conn, s):
            operate(conn, s)
    except Exception as e:
        print(f'error ({addr}): {e}')
    finally:
        if s.wfile:
            s.wfile.close()
        conn.close()
        print(f'disconnected: {addr}')


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(10)
    print(f'RFMP server listening on port {PORT}')
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        print('shutting down')
    finally:
        srv.close()

if __name__ == '__main__':
    main()
