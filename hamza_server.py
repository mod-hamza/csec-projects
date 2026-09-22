# hamza_server.py — RFMP server skeleton
import socket
import threading

HOST = '0.0.0.0'
PORT = 9090

def handle_client(conn, addr):
    print(f'connected: {addr}')
    conn.close()

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(10)
    print(f'listening on {PORT}')
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == '__main__':
    main()

# packet helpers
def send_pkt(conn, *parts):
    msg = '|'.join(str(p) for p in parts) + '\n'
    conn.sendall(msg.encode())

def recv_pkt(conn):
    buf = b''
    while not buf.endswith(b'\n'):
        chunk = conn.recv(4096)
        if not chunk:
            return []
        buf += chunk
    return buf.decode().strip().split('|')
