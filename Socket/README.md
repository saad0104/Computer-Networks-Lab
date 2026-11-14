# Secure File Server & Client (Python sockets)

A beginner-friendly, educational TCP file server/client for authorized devices
on the **same trusted network**. Built only with Python's standard library.

## 1. Project structure

```
Socket/
├── server.py        # TCP server: auth, LIST/UPLOAD/DOWNLOAD/DELETE/QUIT
├── client.py        # interactive CLI client with progress bars
├── config.json      # host, port, token, limits, toggles
├── shared_files/    # server-side file store (created automatically if missing)
└── README.md
```

## 2. What each file does

| File          | Responsibility                                                              |
|---------------|-----------------------------------------------------------------------------|
| `server.py`   | Binds a listening socket, authenticates clients, handles commands, streams file data in 64 KiB chunks, one thread per connection |
| `client.py`   | Connects, authenticates, exposes an interactive shell, streams data with live progress and speed |
| `config.json` | All tunables: address, token, upload limit, delete toggle, rate limits      |
| `shared_files/` | The only directory clients may ever read from or write to                  |

## 3. Configuration (`config.json`)

```json
{
  "host": "0.0.0.0",
  "port": 8000,
  "auth_token": "change-me-to-a-long-random-secret",
  "shared_dir": "shared_files",
  "max_upload_size": 104857600,
  "allow_delete": false,
  "max_connections": 10,
  "auth_fail_limit": 5,
  "auth_fail_window_seconds": 60,
  "idle_timeout_seconds": 300
}
```

| Key | Meaning |
|-----|---------|
| `host` | Bind address. Use `0.0.0.0` (all interfaces), `127.0.0.1` (loopback only), or a private LAN IP like `192.168.1.50` |
| `port` | Listening port |
| `auth_token` | Shared secret. **The client must use the same value.** Change it! |
| `shared_dir` | Where files are stored |
| `max_upload_size` | Reject uploads larger than this (bytes). `104857600` = 100 MB |
| `allow_delete` | If `false`, `DELETE` returns `403`. Turn on only if you want it |
| `max_connections` | Concurrent clients allowed |
| `auth_fail_limit` / `auth_fail_window_seconds` | Per-IP brute-force throttle: after N failed logins within the window, the IP is refused |
| `idle_timeout_seconds` | Disconnect clients that send nothing for this long |

## 4. Running it

Python 3.8+ required. No third-party packages.

### Start the server

```bash
# choose a good token first
#   on the server machine:
python3 server.py

# expected output:
# 2026-08-09 12:00:00,123 [INFO] Listening on 0.0.0.0:8000
```

Server logs show IPs and actions but never the token.

### Start the client (same machine for a loopback test)

```bash
# on the same machine:
python3 client.py
```

The client reads `host`, `port`, and `auth_token` from the same `config.json`.
It will dial `127.0.0.1` when the config `host` is `0.0.0.0`.

### Example session

```
$ python3 client.py
Connecting to 127.0.0.1:8000 ...
[server] 220 Secure file server ready. Send: AUTH <token>
[server] 200 Authenticated
Interactive file client. Type 'help' for commands.

file-client> list
(no files on the server)
0 file(s)

file-client> upload "my notes.txt"
uploading [################----]  80.0%  800.0 KB / 1.0 MB  12.5 MB/s
uploading [####################] 100.0%  1.0 MB / 1.0 MB  11.8 MB/s
[server] 200 Saved my notes.txt (1048576 bytes)
Upload finished: 1.0 MB in 0.09s (average 11.8 MB/s)

file-client> list
  my notes.txt
1 file(s)

file-client> download "my notes.txt" downloads
downloading [####################] 100.0%  1.0 MB / 1.0 MB  24.2 MB/s
Saved to: /home/me/Socket/downloads/my notes.txt
Download finished: 1.0 MB in 0.04s (average 24.2 MB/s)

file-client> quit
bye
```

Note the quotes: `upload "my notes.txt"` keeps a filename with spaces as one
argument. Without quotes it would be split into two arguments.

## 5. The wire protocol

Everything is a sequence of lines ending with CRLF (`\r\n`). Any binary file
payload is always announced in advance by its exact byte count, so each side
knows exactly how many bytes to read next.

```
CLIENT                          SERVER
------                          ------
connect ------------->
                                <-------  220 banner line
AUTH <token>        ----------->
                                <-------  200 Authenticated   (or 401 ...)
LIST                ----------->
                                <-------  200 <count>
                                <-------  name-1
                                <-------  name-2  ... one line per file
UPLOAD <size> <name> ---------->
                                <-------  200 OK              (or 503/400)
<size> raw bytes    ----------->
                                <-------  200 Saved <name> (<size> bytes)
DOWNLOAD <name>     ----------->
                                <-------  200 <size>          (or 404)
<size> raw bytes    <-----------
DELETE <name>       ----------->
                                <-------  200 Deleted <name>  (or 403/404)
QUIT                ----------->
                                <-------  200 Bye
```

Status codes: `2xx` success, `400` bad request, `401` auth failed, `403`
forbidden, `404` not found, `500` server error, `503` too large / busy, `421`
rate-limited.

Key concept: **TCP is a byte stream, not a message stream.** When you `send()`
a 10 000-byte chunk, the receiver may get it in one `recv()`, several pieces,
or combined with the next message. That is why the code uses two helpers:

* `recv_line()` accumulates bytes until it finds a `\r\n` terminator.
* `recv_exact(n)` loops until exactly `n` bytes are received.

Filenames are transmitted as a single line, which means they may contain
spaces but must not contain newlines or path separators.

## 5b. UDP variant (`udp_server.py` / `udp_client.py`)

The same commands over `SOCK_DGRAM` instead of `SOCK_STREAM`. UDP keeps
message boundaries but drops TCP's delivery guarantees, so this variant
rebuilds them on top:

* **Datagram format** — one line header + CRLF + optional binary payload:
  `<req_id> <type> <seq> <total> <text>`. `type` is `REQ` (client→server),
  `REP` (server→client), or `ACK` (server confirms one uploaded chunk).
* **Request/response with retry** — every request gets a random `req_id`;
  the client waits for the matching reply and retransmits on timeout
  (`udp_timeout_seconds`, `udp_max_retries`).
* **Response cache** — the server remembers the reply for each
  `(ip, req_id, seq)` and answers retransmits from memory instead of
  re-executing them. That is what prevents a retried `DATA` packet from
  being written twice.
* **Chunked transfers** — files move in `udp_payload_size`-byte datagrams
  (default 1100, under the ~1472-byte MTU limit). Each chunk is ACKed
  (stop-and-wait) before the next is sent; `seq`/`total` order them.
* **Temp-file uploads** — data is written to `name.part-<tid>` and renamed
  into place only when the whole transfer is confirmed, so a failed or
  aborted upload can never destroy an existing file.

UDP-specific config keys:

| Key | Meaning |
|-----|---------|
| `udp_payload_size` | Bytes of file data per datagram |
| `udp_timeout_seconds` | How long to wait for a reply before retransmitting |
| `udp_max_retries` | Retransmissions before the client gives up |

Note: `AUTH`, `LIST`, `UPLOAD`, `DOWNLOAD`, `DELETE`, `QUIT` behave like the
TCP version, and the same auth token / shared directory are used. Run only
**one** of `server.py` / `udp_server.py` at a time (they share the port).

To see retransmission in action, run a lossy UDP proxy (drops packets
randomly) between client and server; transfers still complete byte-identical.

## 6. Safety and security limitations

**This is NOT safe to expose to the public internet.** It encrypts nothing and
sends the auth token in plain text. Anyone sniffing your network could read the
token and any transferred file. Use it only for learning and on networks you
trust.

Built-in protections:
* pre-shared token authentication
* per-IP brute-force throttle and a connection cap
* upload size limit and idle timeout
* path-traversal defence (`sanitize_filename` + `resolve_shared_path`), so
  `../` can never escape `shared_files/`
* server never logs the token

Real-world improvements (do these before any serious use):
* wrap everything in **TLS** (e.g. `ssl` module with certs) so traffic and the
  token are encrypted
* replace the shared token with per-user credentials and salted password
  hashes (e.g. `argon2`), plus TLS client certificates
* add end-to-end checksums/hashing and resume support for interrupted transfers
* add file permissions/ownership, anti-virus scanning, and disk-quota checks
* rate-limit per authenticated user, not just per IP
* stream file metadata (mtime, size) and handle overwrite policy explicitly

## 7. Testing between two computers you own

1. **Make sure they are on the same LAN** (same router/Wi-Fi). Find the server
   machine's private IP, e.g. `192.168.1.50`:
   ```bash
   ip addr show            # Linux: look at the 'inet 192.168.x.x' line
   ipconfig                # Windows
   ifconfig                # macOS
   ```
2. **On the server machine**, edit `config.json`:
   - set `host` to `"192.168.1.50"` (or leave `0.0.0.0` to bind all interfaces)
   - set a strong `auth_token`
3. **Start the server** there: `python3 server.py`
4. **On the second machine**, copy `client.py` and `config.json` there, then set
   the same `host` (the server's LAN IP) and the identical `auth_token`.
   ```bash
   python3 client.py
   file-client> upload ~/photo.jpg
   ```
5. The firewall on the server machine may block port 8000. For a lab test you
   can allow it for that port only:
   ```bash
   sudo ufw allow 8000/tcp      # Ubuntu/Debian
   # or open inbound TCP 8000 in Windows Defender Firewall / macOS firewall
   ```
6. When you're done, remove the firewall rule (`sudo ufw delete allow 8000/tcp`)
   and turn the server off.

Always test on **loopback first** (both programs on one machine) to verify the
setup before moving to two machines.
