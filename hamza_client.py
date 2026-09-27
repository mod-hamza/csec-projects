# hamza_client.py — RFMP client skeleton
import socket

HOST = '127.0.0.1'
PORT = 9090

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print('connected')
    sock.close()

if __name__ == '__main__':
    main()
