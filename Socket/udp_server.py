#!/usr/bin/env python3
"""UDP file server: the same command set as the TCP version, over UDP.

UDP only provides message boundaries (one ``recvfrom`` == one datagram) and
best-effort delivery. Everything else TCP gives you must be rebuilt here:

* request/response exchanges tagged with a random ``req_id`` so a reply can
  be matched to its request and stale datagrams ignored,
* a small response cache per (ip, req_id, seq) so a retransmitted request
  is answered from memory instead of re-executed - crucially, this is what
  stops a retried DATA packet from being written to the file twice,
* stop-and-wait reliability: every file-data packet is ACKed and the sender
  retransmits after a timeout,
* a per-IP "authenticated" set (there is no connection to carry state).

SECURITY: same warnings as the TCP version - no encryption, the auth token
travels in plaintext. Run it ONLY on a trusted LAN.
"""

import json
import logging
import os
import socket
import threading
import time

LINE_TERMINATOR = b"\r\n"
RECV_BUF = 65535          # large enough for the biggest datagram we accept

log = logging.getLogger("udp_server")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def load_config(path="config.json"):
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)

    defaults = {
        "host": "0.0.0.0",
        "port": 8000,
        "auth_token": "",
        "shared_dir": "shared_files",
        "max_upload_size": 100 * 1024 * 1024,
        "allow_delete": False,
        "auth_fail_limit": 5,
        "auth_fail_window_seconds": 60,
        "idle_timeout_seconds": 300,
        "udp_payload_size": 1100,
    }
    for key, value in defaults.items():
        cfg.setdefault(key, value)

    if not cfg["auth_token"]:
        raise ValueError("auth_token must be set in config.json")
    return cfg


# ---------------------------------------------------------------------------
# Path safety (identical to the TCP server)
# ---------------------------------------------------------------------------
def sanitize_filename(name):
    name = name.strip().replace("\\", "/")
    name = os.path.basename(name)
    if not name or name in (".", ".."):
        raise ValueError("invalid file name")
    if "/" in name or "\x00" in name:
        raise ValueError("file name may not contain path separators")
    return name


def resolve_shared_path(shared_dir, name):
    base = os.path.realpath(shared_dir)
    target = os.path.realpath(os.path.join(base, name))
    if target != base and not target.startswith(base + os.sep):
        raise ValueError("illegal path escapes shared directory")
    return target


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------
class ProtocolError(Exception):
    """Raised when a datagram violates the header format."""


def make_datagram(req_id, mtype, seq, total, text, payload=b""):
    """Build one UDP datagram: header line + CRLF + optional binary payload."""
    header = f"{req_id} {mtype} {seq} {total} {text}".encode("utf-8")
    return header + LINE_TERMINATOR + payload


def parse_datagram(data):
    header, sep, payload = data.partition(LINE_TERMINATOR)
    if not sep:
        raise ProtocolError("missing header terminator")
    parts = header.decode("utf-8", errors="replace").split(" ", 4)
    if len(parts) < 5:
        raise ProtocolError("malformed header")
    try:
        req_id = int(parts[0])
        seq = int(parts[2])
        total = int(parts[3])
    except ValueError:
        raise ProtocolError("non-numeric field in header")
    return req_id, parts[1], seq, total, parts[4], payload


# ---------------------------------------------------------------------------
# Per-IP brute-force throttle (sliding window, from the TCP server)
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, limit, window_seconds):
        self.limit = limit
        self.window = window_seconds
        self.failures = {}
        self.lock = threading.Lock()

    def record_failure(self, ip):
        with self.lock:
            self.failures.setdefault(ip, []).append(time.time())
            self._prune(ip)

    def is_blocked(self, ip):
        with self.lock:
            self._prune(ip)
            return len(self.failures.get(ip, [])) >= self.limit

    def _prune(self, ip):
        cutoff = time.time() - self.window
        self.failures[ip] = [t for t in self.failures.get(ip, []) if t > cutoff]


# ---------------------------------------------------------------------------
# Server state
# ---------------------------------------------------------------------------
class ServerState:
    """Everything the stateless socket loop needs to remember."""

    def __init__(self, config):
        self.config = config
        self.cache = {}              # (ip, req_id, seq) -> datagram bytes
        self.transfers = {}          # (ip, tid) -> in-progress upload
        self.authenticated = set()   # ip addresses that passed AUTH
        self.rate_limiter = RateLimiter(
            config["auth_fail_limit"], config["auth_fail_window_seconds"]
        )

    def remember(self, key, datagram):
        self.cache[key] = datagram
        if len(self.cache) > 10000:   # crude cap; lab-sized traffic
            self.cache.clear()

    def prune(self):
        """Close uploads that have been idle too long and remove partial files."""
        now = time.time()
        timeout = self.config["idle_timeout_seconds"]
        for key, st in list(self.transfers.items()):
            if now - st["last_seen"] <= timeout:
                continue
            ip, tid = key
            self.transfers.pop(key, None)
            if st["fh"] is not None:
                try:
                    st["fh"].close()
                except OSError:
                    pass
            if not st["done"]:
                try:
                    os.remove(st["path"])
                except OSError:
                    pass
            log.warning("Timed out upload %s from %s (partial file removed)", tid, ip)


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------
def reply(state, sock, addr, req_id, seq, total, text, payload=b"", key=None):
    """Send a REP and cache it so a duplicate request gets the same answer."""
    if key is None:
        key = (addr[0], req_id, seq)
    datagram = make_datagram(req_id, "REP", seq, total, text, payload)
    state.remember(key, datagram)
    sock.sendto(datagram, addr)


def touch_transfer(state, ip, cmd, text):
    """A retransmitted DATA/DONE means the transfer is still alive."""
    if cmd not in ("DATA", "DONE"):
        return
    try:
        tid = int(text.rpartition(" ")[2])
    except ValueError:
        return
    st = state.transfers.get((ip, tid))
    if st:
        st["last_seen"] = time.time()


def handle_auth(state, sock, addr, req_id, seq, total, text, payload, key):
    ip = addr[0]
    rl = state.rate_limiter
    if rl.is_blocked(ip):
        log.warning("Refused blocked address %s", ip)
        reply(state, sock, addr, req_id, seq, total,
              "421 Too many failed attempts; try again later", key=key)
        return
    _, _, token = text.partition(" ")
    if token != state.config["auth_token"]:
        rl.record_failure(ip)
        log.warning("Authentication FAILED for %s", ip)   # never log the token
        reply(state, sock, addr, req_id, seq, total, "401 Authentication failed", key=key)
        return
    state.authenticated.add(ip)
    reply(state, sock, addr, req_id, seq, total, "200 Authenticated", key=key)
    log.info("Client authenticated: %s", ip)


def handle_list(state, sock, addr, req_id, seq, total, text, payload, key):
    shared = state.config["shared_dir"]
    os.makedirs(shared, exist_ok=True)
    files = sorted(
        name for name in os.listdir(shared)
        if os.path.isfile(os.path.join(shared, name))
    )
    body = "\n".join(files).encode("utf-8")
    reply(state, sock, addr, req_id, seq, total, f"200 {len(files)}",
          payload=body, key=key)
    log.info("LIST: served %d file(s) to %s", len(files), addr[0])


def handle_upload(state, sock, addr, req_id, seq, total, text, payload, key):
    config = state.config
    try:
        _, _, rest = text.partition(" ")          # drop the command word
        size_str, _, rest = rest.partition(" ")
        size = int(size_str)
        name, _, tid_str = rest.rpartition(" ")
        tid = int(tid_str)
        name = sanitize_filename(name)
    except (ValueError, AttributeError):
        reply(state, sock, addr, req_id, seq, total,
              "400 Malformed UPLOAD command", key=key)
        return

    if size < 0 or size > config["max_upload_size"]:
        reply(state, sock, addr, req_id, seq, total,
              f"503 Size {size} exceeds upload limit", key=key)
        return

    os.makedirs(config["shared_dir"], exist_ok=True)
    target = resolve_shared_path(config["shared_dir"], name)
    temp = target + f".part-{tid}"    # write here, rename on success
    try:
        fh = open(temp, "wb")
    except OSError as exc:
        reply(state, sock, addr, req_id, seq, total,
              f"500 Cannot create file: {exc}", key=key)
        return

    payload_size = config["udp_payload_size"]
    state.transfers[(addr[0], tid)] = {
        "tid": tid,
        "name": name,
        "path": temp,
        "final": target,
        "fh": fh,
        "next_seq": 0,
        "total": (size + payload_size - 1) // payload_size,
        "received": 0,
        "last_seen": time.time(),
        "done": size == 0,
    }
    if size == 0:
        fh.close()
    reply(state, sock, addr, req_id, seq, total, "200 OK", key=key)
    log.info("UPLOAD start: %s (%d bytes) from %s", name, size, addr[0])


def handle_data(state, sock, addr, req_id, seq, total, text, payload, key):
    config = state.config
    try:
        tid = int(text.rpartition(" ")[2])
    except ValueError:
        return
    st = state.transfers.get((addr[0], tid))
    if st is None or st["fh"] is None or st["done"]:
        return                       # unknown/completed transfer: no ACK
    if seq < 0 or seq >= st["total"] or len(payload) > config["udp_payload_size"]:
        return                       # invalid packet: ignore (sender retries)
    if seq != st["next_seq"]:
        return                       # out of order: impossible with stop-and-wait

    st["fh"].write(payload)
    st["received"] += len(payload)
    st["next_seq"] += 1
    st["last_seen"] = time.time()

    ack = make_datagram(req_id, "ACK", seq, total, "OK")
    state.remember(key, ack)
    sock.sendto(ack, addr)

    if st["next_seq"] == st["total"]:
        st["fh"].close()
        st["fh"] = None
        st["done"] = True
        log.info("UPLOAD received: %s (%d bytes) from %s",
                 st["name"], st["received"], addr[0])


def handle_done(state, sock, addr, req_id, seq, total, text, payload, key):
    try:
        tid = int(text.rpartition(" ")[2])
    except ValueError:
        reply(state, sock, addr, req_id, seq, total, "400 Malformed DONE", key=key)
        return

    st = state.transfers.pop((addr[0], tid), None)
    if st is None:
        reply(state, sock, addr, req_id, seq, total, "500 No active upload", key=key)
        return

    if st["fh"] is not None:
        try:
            st["fh"].close()
        except OSError:
            pass
        st["fh"] = None

    if not st["done"]:
        try:
            os.remove(st["path"])            # temp file, not the old one
        except OSError:
            pass
        reply(state, sock, addr, req_id, seq, total,
              "500 Transfer incomplete; partial file removed", key=key)
        return

    try:
        os.replace(st["path"], st["final"])  # atomically publish the file
    except OSError as exc:
        try:
            os.remove(st["path"])
        except OSError:
            pass
        reply(state, sock, addr, req_id, seq, total,
              f"500 Could not finalize file: {exc}", key=key)
        return

    reply(state, sock, addr, req_id, seq, total,
          f"200 Saved {st['name']} ({st['received']} bytes)", key=key)
    log.info("UPLOAD confirmed: %s by %s", st["name"], addr[0])


def handle_download(state, sock, addr, req_id, seq, total, text, payload, key):
    """Announce a file's size so the client knows how many chunks to fetch."""
    config = state.config
    try:
        name = sanitize_filename(text.partition(" ")[2])
    except ValueError as exc:
        reply(state, sock, addr, req_id, seq, total, f"400 {exc}", key=key)
        return

    target = resolve_shared_path(config["shared_dir"], name)
    if not os.path.isfile(target):
        reply(state, sock, addr, req_id, seq, total, "404 File not found", key=key)
        return

    size = os.path.getsize(target)
    reply(state, sock, addr, req_id, seq, total, f"200 {size}", key=key)
    log.info("DOWNLOAD: serving %s (%d bytes) to %s", name, size, addr[0])


def handle_get(state, sock, addr, req_id, seq, total, text, payload, key):
    """Serve one chunk of a file. Self-contained: no transfer state needed."""
    config = state.config
    try:
        _, _, rest = text.partition(" ")          # drop the command word
        name, _, _ = rest.rpartition(" ")         # drop the trailing chunk number
        name = sanitize_filename(name)
    except ValueError as exc:
        reply(state, sock, addr, req_id, seq, total, f"400 {exc}", key=key)
        return

    target = resolve_shared_path(config["shared_dir"], name)
    if not os.path.isfile(target):
        reply(state, sock, addr, req_id, seq, total, "404 File not found", key=key)
        return

    size = os.path.getsize(target)
    payload_size = config["udp_payload_size"]
    expected = (size + payload_size - 1) // payload_size
    if seq < 0 or seq >= expected:
        reply(state, sock, addr, req_id, seq, total,
              "400 Chunk index out of range", key=key)
        return

    try:
        with open(target, "rb") as fh:
            fh.seek(seq * payload_size)
            chunk = fh.read(payload_size)
    except OSError as exc:
        reply(state, sock, addr, req_id, seq, total, f"500 {exc}", key=key)
        return

    reply(state, sock, addr, req_id, seq, total, "200 OK", payload=chunk, key=key)


def handle_delete(state, sock, addr, req_id, seq, total, text, payload, key):
    config = state.config
    if not config["allow_delete"]:
        reply(state, sock, addr, req_id, seq, total,
              "403 DELETE is disabled on this server", key=key)
        return
    try:
        name = sanitize_filename(text.partition(" ")[2])
    except ValueError as exc:
        reply(state, sock, addr, req_id, seq, total, f"400 {exc}", key=key)
        return

    target = resolve_shared_path(config["shared_dir"], name)
    if not os.path.isfile(target):
        reply(state, sock, addr, req_id, seq, total, "404 File not found", key=key)
        return
    try:
        os.remove(target)
    except OSError as exc:
        reply(state, sock, addr, req_id, seq, total,
              f"500 Could not delete: {exc}", key=key)
        return
    reply(state, sock, addr, req_id, seq, total, f"200 Deleted {name}", key=key)
    log.info("DELETE: %s by %s", name, addr[0])


# ---------------------------------------------------------------------------
# Datagram dispatch loop
# ---------------------------------------------------------------------------
def handle_datagram(sock, data, addr, state):
    req_id, mtype, seq, total, text, payload = parse_datagram(data)
    if mtype != "REQ":
        return                        # ignore stray ACK/REP packets
    ip = addr[0]
    key = (ip, req_id, seq)
    cmd = text.split(" ", 1)[0].upper()

    touch_transfer(state, ip, cmd, text)

    if key in state.cache:            # duplicate request -> resend cached answer
        sock.sendto(state.cache[key], addr)
        return

    if cmd != "AUTH" and ip not in state.authenticated:
        reply(state, sock, addr, req_id, seq, total,
              "401 Authentication required", key=key)
        return

    if cmd == "AUTH":
        handle_auth(state, sock, addr, req_id, seq, total, text, payload, key)
    elif cmd == "LIST":
        handle_list(state, sock, addr, req_id, seq, total, text, payload, key)
    elif cmd == "UPLOAD":
        handle_upload(state, sock, addr, req_id, seq, total, text, payload, key)
    elif cmd == "DATA":
        handle_data(state, sock, addr, req_id, seq, total, text, payload, key)
    elif cmd == "DONE":
        handle_done(state, sock, addr, req_id, seq, total, text, payload, key)
    elif cmd == "DOWNLOAD":
        handle_download(state, sock, addr, req_id, seq, total, text, payload, key)
    elif cmd == "GET":
        handle_get(state, sock, addr, req_id, seq, total, text, payload, key)
    elif cmd == "DELETE":
        handle_delete(state, sock, addr, req_id, seq, total, text, payload, key)
    elif cmd == "QUIT":
        state.authenticated.discard(ip)
        reply(state, sock, addr, req_id, seq, total, "200 Bye", key=key)
    else:
        reply(state, sock, addr, req_id, seq, total, "400 Unknown command", key=key)


def serve_forever(config):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((config["host"], config["port"]))
    log.info("UDP listening on %s:%s", config["host"], config["port"])

    state = ServerState(config)
    try:
        while True:
            state.prune()
            try:
                data, addr = sock.recvfrom(RECV_BUF)
            except (socket.timeout, BlockingIOError):
                continue
            try:
                handle_datagram(sock, data, addr, state)
            except ProtocolError as exc:
                log.info("Protocol error from %s: %s", addr[0], exc)
            except Exception:
                log.exception("Error handling %s", addr[0])
    except KeyboardInterrupt:
        log.info("Shutting down")
    finally:
        sock.close()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    try:
        config = load_config()
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        log.error("Configuration error: %s", exc)
        return
    serve_forever(config)


if __name__ == "__main__":
    main()
