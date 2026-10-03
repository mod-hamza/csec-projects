# hamza_client.py
# RFMP Client - Spring 2026
# Group: Hamza (415001013), Akour (433002101), Kawtar (433006015), Aya (433000484)
#
# Run this to connect to the RFMP server. It will ask you:
#   - Server IP and port
#   - Whether to use encryption
#   - Which algorithm (AES or Caesar)
# Then you get a menu to send commands.

import socket
import base64

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 9090


# ── packet helpers ───────────────────────────────────────────────────────────

def send_pkt(sock, *parts):
    """
    Sends a packet to the server.

    Pipes join all the arguments and puts a newline at the end.
    This is how our protocol works, where every packet is a
    single line of data with fields separated by pipes. The
    server reads until the newline character is encountered.
    Example: send_pkt(sock, 'CM', 'openRead', 'data.txt') sends "CM|openRead|data.txt\n"
    """
    msg = '|'.join(str(p) for p in parts) + '\n'
    sock.sendall(msg.encode())

def recv_pkt(sock):
    """
    Reads one packet from the server and returns a list of fields.

    Keeps reading chunks until we get a newline, which signals the end
    of the packet. Then we decode, strip whitespace, and split on pipes.
    Returns an empty list if the server closed the connection.
    """
    buf = b''
    while not buf.endswith(b'\n'):
        chunk = sock.recv(4096)
        if not chunk:
            return []
        buf += chunk
    return buf.decode().strip().split('|')


# ── Caesar cipher ────────────────────────────────────────────────────────────

def caesar(text, shift):
    """
    Basic Caesar cipher — shifts each letter by 'shift' positions.
    Anything that isn't a letter (spaces, numbers, punctuation) stays as-is.

    We use shift=13 (ROT13) as default. Decrypting is just passing -13,
    so the same function handles both directions.
    """
    out = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            out.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            out.append(ch)
    return ''.join(out)


# ── AES cipher ───────────────────────────────────────────────────────────────

def aes_enc(text, key):
    """
    Encrypts text with AES-CBC using a random IV each time.

    We prepend the 16-byte IV to the ciphertext before base64-encoding
    the whole thing into a string. That way the receiver can pull the IV
    off the front without us needing to send it separately.
    """
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(text.encode(), 16))
    return base64.b64encode(iv + ct).decode()

def aes_dec(b64, key):
    """
    Decrypts a base64 string produced by aes_enc.

    We base64-decode first, take the first 16 bytes as the IV,
    then decrypt the rest and remove the padding to get the original text.
    """
    raw = base64.b64decode(b64)
    cipher = AES.new(key, AES.MODE_CBC, raw[:16])
    return unpad(cipher.decrypt(raw[16:]), 16).decode()


# ── session state ────────────────────────────────────────────────────────────

class Session:
    """
    Stores the encryption state for this connection.

    Once setup() runs, this object knows whether we're encrypted,
    which algorithm we're using, and what the session key is.
    enc() and dec() check this before doing anything so they can
    silently pass through if we're running unencrypted.
    """
    def __init__(self):
        self.secured = False
        self.algo = None
        self.key = None     # bytes (AES) or int (Caesar)

def enc(text, s):
    """
    Encrypts text if the session is secured, otherwise returns it unchanged.
    Routes to AES or Caesar depending on what was negotiated during setup.
    """
    if not s.secured:
        return text
    if s.algo == 'AES':
        return aes_enc(text, s.key)
    return caesar(text, s.key)

def dec(text, s):
    """
    Decrypts text if the session is secured.
    For Caesar, decryption is just a negative shift.
    If AES decryption fails for any reason, we return the text as-is
    rather than crashing
    """
    if not s.secured:
        return text
    if s.algo == 'AES':
        try:
            return aes_dec(text, s.key)
        except Exception:
            return text
    return caesar(text, -s.key)


# ── setup phase ──────────────────────────────────────────────────────────────
# Sends SS, waits for CC, then (if secure) sends EC with encrypted session key.

def setup(sock, secure, algo):
    """
    Runs the RFMP handshake with the server.

    We send SS to say hello. If we want encryption, the server sends back
    its RSA public key in the CC packet. We generate a session key (random
    bytes for AES, or just the number 13 for Caesar), encrypt it with the
    server's public key, and send it back in EC. From that point on, all
    data goes through enc()/dec().

    Returns a Session object on success, or None if something went wrong.
    """
    send_pkt(sock, 'SS', 'RFMP', 'v1.0', '1' if secure else '0')

    pkt = recv_pkt(sock)
    if not pkt or pkt[0] != 'CC':
        print('bad response from server during setup')
        return None

    s = Session()
    if not secure:
        return s

    # pull server's public key from the CC packet
    server_pub = RSA.import_key(base64.b64decode(pkt[1]))

    algo = algo.upper()
    s.algo = algo

    # generate the session key we'll use for data encryption
    if algo == 'AES':
        raw_key = get_random_bytes(16)   # 128-bit AES key
        s.key = raw_key
    else:
        # Caesar: pick a shift value, encode it as bytes for RSA transport
        s.key = 13
        raw_key = b'13'

    # encrypt the session key with server's RSA public key
    enc_key = base64.b64encode(PKCS1_OAEP.new(server_pub).encrypt(raw_key)).decode()

    # generate our own RSA key pair (server needs our public key)
    our_rsa = RSA.generate(2048)
    our_pub_b64 = base64.b64encode(our_rsa.publickey().export_key()).decode()

    send_pkt(sock, 'EC', algo, enc_key, f'client:{our_pub_b64}')

    s.secured = True
    return s


# ── display server response ──────────────────────────────────────────────────

def show(pkt, s):
    """
    Prints the server's response in a readable format.

    SC means success, DP means file data, EE means error. For SC and DP
    we try to decrypt the payload first in case the session is encrypted.
    The try/except on dec() is just for safety: if it fails for some
    reason, we print what we got rather than crashing.
    """
    if not pkt:
        print('no response')
        return
    ptype = pkt[0].strip().upper()
    payload = pkt[1] if len(pkt) > 1 else ''

    if ptype == 'SC':
        try:
            payload = dec(payload, s)
        except Exception:
            pass
        print(f'[OK] {payload}')

    elif ptype == 'DP':
        try:
            payload = dec(payload, s)
        except Exception:
            pass
        print(f'\n--- file contents ---\n{payload}\n---')

    elif ptype == 'EE':
        code = pkt[1] if len(pkt) > 1 else '?'
        desc = pkt[2] if len(pkt) > 2 else '?'
        print(f'[error {code}] {desc}')

    else:
        print(f'[?] {pkt}')


# ── main ─────────────────────────────────────────────────────────────────────

def main():
    """
    Entry point it asks for connection details, runs setup, then sits in
    the command loop until the user quits.

    Commands:
      prompt <cmd>   — run a shell command on the server
      read <file>    — read a file from the server
      write <file>   — write a file to the server (type content, then DONE)
      quit           — send END and close the connection
    """
    ip = input(f'server IP [{HOST}]: ').strip() or HOST
    port_in = input(f'port [{PORT}]: ').strip()
    port = int(port_in) if port_in else PORT

    secure = input('use encryption? (y/n) [n]: ').strip().lower() == 'y'
    algo = 'AES'
    if secure:
        algo = input('algorithm (AES/CAESAR) [AES]: ').strip().upper() or 'AES'

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((ip, port))
    except ConnectionRefusedError:
        print(f'could not connect to {ip}:{port}')
        return

    s = setup(sock, secure, algo)
    if not s:
        sock.close()
        return

    mode = 'secured' if s.secured else 'unsecured'
    print(f'\nconnected ({mode}). commands: prompt, read, write, quit\n')

    while True:
        line = input('rfmp> ').strip()

        if not line:
            continue

        if line in ('quit', 'q', 'exit'):
            send_pkt(sock, 'END')
            show(recv_pkt(sock), s)
            break

        # prompt <command>  — run a shell command on the server
        elif line.startswith('prompt '):
            cmd = line[7:]
            send_pkt(sock, 'CM', 'prompt', cmd)
            show(recv_pkt(sock), s)

        # read <filename>  — read a file from the server
        elif line.startswith('read '):
            fname = line[5:]
            send_pkt(sock, 'CM', 'openRead', fname)
            show(recv_pkt(sock), s)

        # write <filename>  — write a file on the server
        elif line.startswith('write '):
            fname = line[6:]
            send_pkt(sock, 'CM', 'openWrite', fname)
            show(recv_pkt(sock), s)
            print('type your data, then type DONE on its own line:')
            lines = []
            while True:
                ln = input()
                if ln.strip().upper() == 'DONE':
                    break
                lines.append(ln)
            data = enc('\n'.join(lines), s)
            send_pkt(sock, 'DP', data)
            show(recv_pkt(sock), s)

        else:
            print('commands: prompt <cmd>, read <file>, write <file>, quit')

    sock.close()
    print('disconnected')

if __name__ == '__main__':
    main()
