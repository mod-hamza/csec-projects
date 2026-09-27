# hamza_client.py — setup phase
import socket, base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 9090

def send_pkt(sock, *parts):
    sock.sendall(('|'.join(str(p) for p in parts) + '\n').encode())

def recv_pkt(sock):
    buf = b''
    while not buf.endswith(b'\n'):
        c = sock.recv(4096)
        if not c: return []
        buf += c
    return buf.decode().strip().split('|')

class Session:
    def __init__(self):
        self.secured = False; self.algo = None; self.key = None

def setup(sock, secure=False, algo='AES'):
    send_pkt(sock, 'SS', 'RFMP', 'v1.0', '1' if secure else '0')
    pkt = recv_pkt(sock)
    if not pkt or pkt[0] != 'CC': return None
    s = Session()
    if not secure: return s
    server_pub = RSA.import_key(base64.b64decode(pkt[1]))
    algo = algo.upper(); s.algo = algo
    if algo == 'AES':
        raw = get_random_bytes(16); s.key = raw
    else:
        raw = b'13'; s.key = 13
    enc_key = base64.b64encode(PKCS1_OAEP.new(server_pub).encrypt(raw)).decode()
    our_rsa = RSA.generate(2048)
    pub_b64 = base64.b64encode(our_rsa.publickey().export_key()).decode()
    send_pkt(sock, 'EC', algo, enc_key, f'client:{pub_b64}')
    s.secured = True; return s

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    s = setup(sock, False)
    print('session:', s.secured)
    sock.close()

if __name__ == '__main__': main()

# command helpers — added by Aya
def send_cmd(sock, cmd_type, args):
    sock.sendall(f'CM|{cmd_type}|{args}\n'.encode())

def read_response(sock):
    buf = b''
    while not buf.endswith(b'\n'):
        c = sock.recv(4096)
        if not c: break
        buf += c
    return buf.decode().strip().split('|')
