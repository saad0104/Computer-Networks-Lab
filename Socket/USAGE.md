# Usage — running the server, client, and accessing files

Both variants share `config.json` (host, port, auth_token). Use the same
`auth_token` on every machine that connects. Only run one server at a time
(both bind port 8000).

## TCP variant

```bash
python3 server.py        # terminal 1 - start the server
python3 client.py        # terminal 2 - start the client
```

## UDP variant

```bash
python3 udp_server.py    # terminal 1 - start the server
python3 udp_client.py    # terminal 2 - start the client
```

## Client commands

| Command | What it does |
|---------|--------------|
| `list` | Show files on the server |
| `upload <local-file> [remote-name]` | Send a file (optionally renamed) |
| `download <remote-file> [save-as-or-dir]` | Receive a file |
| `delete <remote-file>` | Delete a file (needs `"allow_delete": true` in config) |
| `help` | List commands |
| `quit` / `exit` | Disconnect and leave |

### Examples

```bash
file-client> list
file-client> upload /home/me/photo.jpg
file-client> upload "my notes.txt"          # quote names with spaces
file-client> download photo.jpg downloads
file-client> delete photo.jpg
```

## Two computers on the same LAN

1. On the server machine, set a strong `auth_token` in `config.json`.
2. Start the server: `python3 server.py` (or `udp_server.py`).
3. On the second machine, copy `client.py` (or `udp_client.py`) + `config.json`
   and set `host` to the server's LAN IP (e.g. `192.168.1.50`).
4. Start the client and run the commands above.

Files are stored on the server in `shared_files/`.
