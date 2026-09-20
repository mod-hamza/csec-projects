# RFMP Protocol Reference

## Packet types
- SS  : Start (client -> server)
- CC  : Confirm connection (server -> client)
- EC  : Encryption setup (client -> server)
- CM  : Command (client -> server)
- DP  : Data packet
- SC  : Success
- EE  : Error/exception
- END : Close session

## Error codes
- E001: unknown or malformed packet
- E002: file not found
- E003: permission denied
- E004: command failed
