# hamza_server.py — setup phase added (SS/CC handshake)
import socket, threading, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
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

class Session:
    def __init__(self):
        self.secured = False
        self.algo = None
        self.key = None
        self.rsa = None
        self.wfile = None

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
    return True

def handle_client(conn, addr):
    print(f'connected: {addr}')
    s = Session()
    setup(conn, s)
    conn.close()

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT)); srv.listen(10)
    print(f'listening on {PORT}')
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__': main()
