# csec-projects
RFMP — Remote File Management Protocol

Spring 2026 socket programming project.
Group: Hamza (415001013), Akour (433002101), Kawtar (433006015), Aya (433000484)

## Files
- `hamza_server.py` — Python RFMP server (multithreaded, RSA + AES/Caesar)
- `hamza_client.py` — Python client (interactive, all commands)
- `hamza_client.c`  — C client (no encryption, openRead only)
- `PROTOCOL.md`     — packet format reference

## Run
```bash
pip install pycryptodome

# terminal 1 — start the server
python3 hamza_server.py

# terminal 2 — Python client
python3 hamza_client.py

# C client (read a file)
make
./rfmp_c 127.0.0.1 9090 data.txt
```

## Encryption
Pick AES or Caesar when prompted. Both use RSA to exchange the session key
during setup — the session key then encrypts all file data.
