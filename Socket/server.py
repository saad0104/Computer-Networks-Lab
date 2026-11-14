#!/usr/bin/env python3
"""Secure file server for a trusted LAN.

A beginner-friendly demonstration of TCP socket programming with Python's
built-in ``socket`` module. Concepts shown:

* ``socket()`` / ``bind()`` / ``listen()`` / ``accept()``  ->  setting up a server
* ``sendall()`` / ``recv()``                              ->  sending and receiving
* Thread-per-connection concurrency                       ->  serving many clients
* A newline-delimited, length-prefixed text protocol      ->  framing messages
* Path-traversal protection and a pre-shared auth token   ->  basic security

SECURITY WARNING: this sends the auth token in plain text and encrypts nothing.
Run it ONLY on networks you trust (localhost or your own LAN). It is NOT a
substitute for TLS. See README.md for details.
"""

import json
import logging
import os
import socket
import threading
import time

BUFFER_SIZE = 4096          # bytes read per recv() call
CHUNK_SIZE = 64 * 1024      # 64 KiB, bytes streamed per chunk during file transfer
LINE_TERMINATOR = b"\r\n"
MAX_LINE_LENGTH = 64 * 1024

log = logging.getLogger("server")


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def load_config(path="config.json"):
    """Load config.json, filling in defaults for any missing keys."""
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)

    defaults = {
        "host": "0.0.0.0",
        "port": 8000,
        "auth_token": "",
        "shared_dir": "shared_files",
        "max_upload_size": 100 * 1024 * 1024,
        "allow_delete": False,
        "max_connections": 10,
        "auth_fail_limit": 5,
        "auth_fail_window_seconds": 60,
        "idle_timeout_seconds": 300,
    }
    for key, value in defaults.items():
        cfg.setdefault(key, value)

    if not cfg["auth_token"]:
        raise ValueError("auth_token must be set in config.json")
    return cfg


# ---------------------------------------------------------------------------
# Path safety
# ---------------------------------------------------------------------------
def sanitize_filename(name):
    """Reduce any client-supplied name to a plain file name.

    Replaces backslashes (Windows) with forward slashes, then takes only the
    final path component. This defeats tricks like ``../../etc/passwd``.
    """
    name = name.strip().replace("\\", "/")
    name = os.path.basename(name)
    if not name or name in (".", ".."):
        raise ValueError("invalid file name")
    if "/" in name or "\x00" in name:
        raise ValueError("file name may not contain path separators")
    return name


def resolve_shared_path(shared_dir, name):
    """Join shared_dir + name and verify the result is still inside shared_dir.

    This is a second layer of defence in depth on top of sanitize_filename().
    """
    base = os.path.realpath(shared_dir)
    target = os.path.realpath(os.path.join(base, name))
    if target != base and not target.startswith(base + os.sep):
        raise ValueError("illegal path escapes shared directory")
    return target


# ---------------------------------------------------------------------------
# Simple rate limiter (per-IP, sliding window)
# ---------------------------------------------------------------------------
class RateLimiter:
    """Tracks recent failed logins per IP address and blocks repeat offenders."""

    def __init__(self, limit, window_seconds):
        self.limit = limit
        self.window = window_seconds
        self.failures = {}          # ip -> list of failure timestamps
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
# Protocol errors
# ---------------------------------------------------------------------------
class ProtocolError(Exception):
    """Raised when the client violates the message framing rules."""


# ---------------------------------------------------------------------------
# Per-client connection handler
# ---------------------------------------------------------------------------
class ClientConnection:
    """Handles every protocol exchange for a single connected client.

    One instance runs in its own thread. All state lives on this instance,
    so different clients can never interfere with each other.
    """

    def __init__(self, conn, addr, config, rate_limiter):
        self.conn = conn
        self.addr = addr                      # (ip, port) tuple
        self.config = config
        self.rate_limiter = rate_limiter
        self.buffer = b""                     # left-over bytes from previous reads

    # ---- low-level socket IO -------------------------------------------

    def send_all(self, data):
        """Send str (encoded) or bytes, retrying until everything is sent."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.conn.sendall(data)               # sendall loops until all bytes are out

    def send_line(self, text):
        """Send one command/status line followed by CRLF."""
        self.send_all(text.encode("utf-8") + LINE_TERMINATOR)

    def recv_line(self):
        """Read exactly one line, terminated by CRLF.

        recv() does not guarantee you get a whole line in one call, so we
        accumulate bytes in self.buffer until we find the terminator.
        """
        while LINE_TERMINATOR not in self.buffer:
            chunk = self.conn.recv(BUFFER_SIZE)
            if not chunk:                     # empty recv() == peer closed socket
                raise ProtocolError("client closed the connection")
            self.buffer += chunk
            if len(self.buffer) > MAX_LINE_LENGTH:
                raise ProtocolError("line too long")
        line, self.buffer = self.buffer.split(LINE_TERMINATOR, 1)
        return line.decode("utf-8", errors="replace")

    def recv_exact(self, size):
        """Read exactly `size` bytes, honouring partial reads.

        This is how we safely receive binary file data: we always know the
        byte count up front (sent in the header line) and loop until we have
        every byte.
        """
        data = b""
        remaining = size
        if self.buffer:                       # use any bytes we already read
            take = min(len(self.buffer), remaining)
            data, self.buffer = self.buffer[:take], self.buffer[take:]
            remaining -= take
        while remaining > 0:
            chunk = self.conn.recv(min(BUFFER_SIZE, remaining))
            if not chunk:
                raise ProtocolError("client closed during file transfer")
            data += chunk
            remaining -= len(chunk)
        return data

    def read_command(self, expected):
        """Read a line, split off the command word and return the argument.

        e.g. AUTH mysecret       -> ("AUTH", "mysecret")
             UPLOAD 123 f.txt    -> ("UPLOAD", "123 f.txt")
        """
        line = self.recv_line()
        command, _, arg = line.partition(" ")
        if command.upper() != expected:
            raise ProtocolError(f"expected {expected}, received {command}")
        return arg

    # ---- top-level connection lifecycle --------------------------------

    def handle(self):
        ip = self.addr[0]
        log.info("Connection from %s:%d", ip, self.addr[1])
        try:
            if self.rate_limiter.is_blocked(ip):
                self.send_line("421 Too many failed attempts; try again later")
                log.warning("Refused blocked address %s", ip)
                return

            self.conn.settimeout(30)                     # time to send AUTH
            self.send_line("220 Secure file server ready. Send: AUTH <token>")
            token = self.read_command("AUTH")

            if token != self.config["auth_token"]:
                self.rate_limiter.record_failure(ip)
                self.send_line("401 Authentication failed")
                log.warning("Authentication FAILED for %s", ip)   # never log the token
                return

            self.conn.settimeout(self.config["idle_timeout_seconds"])
            self.send_line("200 Authenticated")
            log.info("Client authenticated: %s", ip)
            self.command_loop()

        except ProtocolError as exc:
            log.info("Client %s protocol error: %s", ip, exc)
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError) as exc:
            log.info("Client %s disconnected: %s", ip, exc)
        finally:
            try:
                self.conn.close()
            except OSError:
                pass
            log.info("Connection closed for %s", ip)

    def command_loop(self):
        while True:
            line = self.recv_line()
            if not line:
                break
            command, _, arg = line.partition(" ")
            command = command.upper()

            if command == "LIST":
                self.cmd_list()
            elif command == "UPLOAD":
                self.cmd_upload(arg)
            elif command == "DOWNLOAD":
                self.cmd_download(arg)
            elif command == "DELETE":
                self.cmd_delete(arg)
            elif command == "QUIT":
                self.send_line("200 Bye")
                log.info("Client %s sent QUIT", self.addr[0])
                return
            else:
                self.send_line("400 Unknown command")

    # ---- individual commands -------------------------------------------

    def cmd_list(self):
        shared = self.config["shared_dir"]
        os.makedirs(shared, exist_ok=True)
        files = sorted(
            name for name in os.listdir(shared)
            if os.path.isfile(os.path.join(shared, name))
        )
        self.send_line(f"200 {len(files)}")               # count first
        for name in files:
            self.send_line(name)                          # one file per line
        log.info("LIST: served %d file(s) to %s", len(files), self.addr[0])

    def cmd_upload(self, arg):
        size_str, _, name = arg.partition(" ")
        try:
            size = int(size_str)
        except ValueError:
            self.send_line("400 Invalid file size")
            return

        if size < 0 or size > self.config["max_upload_size"]:
            self.send_line(f"503 Size {size} exceeds upload limit")
            return

        try:
            name = sanitize_filename(name)
        except ValueError as exc:
            self.send_line(f"400 {exc}")
            return

        os.makedirs(self.config["shared_dir"], exist_ok=True)
        target = resolve_shared_path(self.config["shared_dir"], name)

        self.send_line("200 OK")                          # green light to send data
        received = 0
        try:
            with open(target, "wb") as fh:
                remaining = size
                while remaining > 0:
                    chunk = self.recv_exact(min(CHUNK_SIZE, remaining))
                    fh.write(chunk)
                    received += len(chunk)
                    remaining -= len(chunk)
        except OSError as exc:
            self.send_line(f"500 Could not save file: {exc}")
            try:
                os.remove(target)
            except OSError:
                pass
            return

        self.send_line(f"200 Saved {name} ({received} bytes)")
        log.info("UPLOAD: %s (%d bytes) from %s", name, received, self.addr[0])

    def cmd_download(self, name):
        try:
            name = sanitize_filename(name)
        except ValueError as exc:
            self.send_line(f"400 {exc}")
            return

        target = resolve_shared_path(self.config["shared_dir"], name)
        if not os.path.isfile(target):
            self.send_line("404 File not found")
            return

        size = os.path.getsize(target)
        self.send_line(f"200 {size}")                     # announce byte count
        try:
            with open(target, "rb") as fh:
                remaining = size
                while remaining > 0:
                    chunk = fh.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    self.send_all(chunk)
                    remaining -= len(chunk)
        except OSError as exc:
            self.send_line(f"500 {exc}")
            return

        log.info("DOWNLOAD: %s (%d bytes) to %s", name, size, self.addr[0])

    def cmd_delete(self, name):
        if not self.config["allow_delete"]:
            self.send_line("403 DELETE is disabled on this server")
            return
        try:
            name = sanitize_filename(name)
        except ValueError as exc:
            self.send_line(f"400 {exc}")
            return

        target = resolve_shared_path(self.config["shared_dir"], name)
        if not os.path.isfile(target):
            self.send_line("404 File not found")
            return
        try:
            os.remove(target)
        except OSError as exc:
            self.send_line(f"500 Could not delete: {exc}")
            return
        self.send_line(f"200 Deleted {name}")
        log.info("DELETE: %s by %s", name, self.addr[0])


# ---------------------------------------------------------------------------
# Server main loop
# ---------------------------------------------------------------------------
def serve_forever(config):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)   # avoid TIME_WAIT hang-ups
    server.bind((config["host"], config["port"]))
    server.listen(config["max_connections"])                       # OS accept queue size
    log.info("Listening on %s:%s", config["host"], config["port"])

    rate_limiter = RateLimiter(
        config["auth_fail_limit"], config["auth_fail_window_seconds"]
    )
    state = {"active": 0}
    state_lock = threading.Lock()

    def handle_client(conn, addr):
        try:
            ClientConnection(conn, addr, config, rate_limiter).handle()
        finally:
            with state_lock:
                state["active"] -= 1

    try:
        while True:
            conn, addr = server.accept()                   # blocks until a client connects
            with state_lock:
                if state["active"] >= config["max_connections"]:
                    log.warning("Connection limit reached; refusing %s", addr[0])
                    try:
                        conn.sendall(b"503 Server busy\r\n")
                    except OSError:
                        pass
                    conn.close()
                    continue
                state["active"] += 1
            threading.Thread(
                target=handle_client,
                args=(conn, addr),
                daemon=True,                               # dies with the main thread
            ).start()
    except KeyboardInterrupt:
        log.info("Shutting down")
    finally:
        server.close()


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
