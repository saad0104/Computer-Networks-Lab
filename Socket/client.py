#!/usr/bin/env python3
"""Interactive client for the secure file server.

Mirrors the server's message protocol (newline-delimited text commands,
length-prefixed binary payloads) so the two sides always agree on where
commands and file data begin and end.
"""

import json
import os
import shlex
import socket
import sys
import time

BUFFER_SIZE = 4096
CHUNK_SIZE = 64 * 1024      # keep in sync with the server
LINE_TERMINATOR = b"\r\n"
MAX_LINE_LENGTH = 64 * 1024


class ServerError(Exception):
    """Raised when the server replies with an error status code (>= 400)."""


class ClientError(Exception):
    """Raised for local client-side problems (bad file names, etc.)."""


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------
def load_config(path="config.json"):
    defaults = {
        "host": "127.0.0.1",
        "port": 8000,
        "auth_token": "",
        "max_upload_size": 100 * 1024 * 1024,
    }
    try:
        with open(path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
    except FileNotFoundError:
        cfg = {}
    for key, value in defaults.items():
        cfg.setdefault(key, value)
    return cfg


def sanitize_filename(name):
    """Accept only a plain file name; strip anything that looks like a path."""
    name = name.strip().replace("\\", "/")
    name = os.path.basename(name)
    if not name or name in (".", ".."):
        raise ClientError("invalid file name")
    if "/" in name or "\x00" in name:
        raise ClientError("file name may not contain path separators")
    return name


def format_size(num):
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


def print_progress(done, total, start_time, action):
    """Rewrite a single progress line in place using carriage return."""
    if total <= 0:
        return
    elapsed = time.time() - start_time
    speed = done / elapsed if elapsed > 0 else 0
    percent = done / total * 100
    bar_len = 20
    filled = int(bar_len * percent / 100)
    bar = "#" * filled + "-" * (bar_len - filled)
    line = (f"\r{action} [{bar}] {percent:5.1f}%  "
            f"{format_size(done)} / {format_size(total)}  "
            f"{format_size(speed)}/s   ")
    sys.stdout.write(line)
    sys.stdout.flush()


def print_stats(done, start_time, action):
    elapsed = time.time() - start_time
    speed = done / elapsed if elapsed > 0 else 0
    print(f"\n{action} finished: {format_size(done)} in {elapsed:.1f}s "
          f"(average {format_size(speed)}/s)")


# ---------------------------------------------------------------------------
# The client
# ---------------------------------------------------------------------------
class FileClient:
    """Owns the socket and speaks the file protocol."""

    def __init__(self, host, port, token, config):
        self.host = host
        self.port = port
        self.token = token
        self.config = config
        self.sock = None
        self.buffer = b""

    # ---- socket helpers (mirror the server side) ------------------------

    def send_all(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.sock.sendall(data)

    def send_line(self, text):
        self.send_all(text.encode("utf-8") + LINE_TERMINATOR)

    def recv_line(self):
        while LINE_TERMINATOR not in self.buffer:
            chunk = self.sock.recv(BUFFER_SIZE)
            if not chunk:
                raise ServerError("server closed the connection")
            self.buffer += chunk
            if len(self.buffer) > MAX_LINE_LENGTH:
                raise ServerError("server sent an over-long line")
        line, self.buffer = self.buffer.split(LINE_TERMINATOR, 1)
        return line.decode("utf-8", errors="replace")

    def recv_exact(self, size):
        data = b""
        remaining = size
        if self.buffer:
            take = min(len(self.buffer), remaining)
            data, self.buffer = self.buffer[:take], self.buffer[take:]
            remaining -= take
        while remaining > 0:
            chunk = self.sock.recv(min(BUFFER_SIZE, remaining))
            if not chunk:
                raise ServerError("server closed during file transfer")
            data += chunk
            remaining -= len(chunk)
        return data

    def expect_ok(self, line):
        code = int(line.split(" ", 1)[0])
        if code >= 400:
            raise ServerError(line)

    # ---- connection lifecycle -------------------------------------------

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=15)
        self.sock.settimeout(None)               # interactive: no idle cut-off
        banner = self.recv_line()
        print(f"[server] {banner}")
        self.send_line(f"AUTH {self.token}")
        reply = self.recv_line()
        self.expect_ok(reply)
        print(f"[server] {reply}")

    def close(self):
        if self.sock:
            try:
                self.send_line("QUIT")
                self.recv_line()                 # swallow the Bye reply
            except (OSError, ServerError):
                pass
            try:
                self.sock.close()
            except OSError:
                pass

    # ---- commands --------------------------------------------------------

    def list_files(self):
        self.send_line("LIST")
        reply = self.recv_line()
        self.expect_ok(reply)
        count = int(reply.split(" ", 1)[1])
        names = [self.recv_line() for _ in range(count)]
        return names

    def upload(self, local_path, remote_name=None):
        local_path = os.path.expanduser(local_path)
        if not os.path.isfile(local_path):
            raise ClientError(f"local file not found: {local_path}")

        size = os.path.getsize(local_path)
        remote_name = remote_name or os.path.basename(local_path)
        try:
            remote_name = sanitize_filename(remote_name)
        except ClientError as exc:
            raise ClientError(str(exc)) from None

        if size > self.config["max_upload_size"]:
            raise ClientError(
                f"file is {format_size(size)} but the local limit is "
                f"{format_size(self.config['max_upload_size'])}"
            )

        self.send_line(f"UPLOAD {size} {remote_name}")
        reply = self.recv_line()
        self.expect_ok(reply)

        start = time.time()
        sent = 0
        with open(local_path, "rb") as fh:
            while True:
                chunk = fh.read(CHUNK_SIZE)
                if not chunk:
                    break
                self.sock.sendall(chunk)
                sent += len(chunk)
                print_progress(sent, size, start, "uploading")
        print()
        reply = self.recv_line()                 # final "200 Saved ..."
        self.expect_ok(reply)
        print(f"[server] {reply}")
        print_stats(sent, start, "Upload")

    def download(self, remote_name, local_target=None):
        try:
            remote_name = sanitize_filename(remote_name)
        except ClientError as exc:
            raise ClientError(str(exc)) from None

        self.send_line(f"DOWNLOAD {remote_name}")
        reply = self.recv_line()
        self.expect_ok(reply)
        size = int(reply.split(" ", 1)[1])

        if local_target is None:
            local_target = "."
        local_target = os.path.expanduser(local_target)
        if os.path.isdir(local_target) or local_target.endswith(os.sep):
            local_path = os.path.join(local_target, remote_name)
        else:
            local_path = local_target
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
        start = time.time()
        received = 0
        with open(local_path, "wb") as fh:
            while received < size:
                chunk = self.recv_exact(min(CHUNK_SIZE, size - received))
                fh.write(chunk)
                received += len(chunk)
                print_progress(received, size, start, "downloading")
        print()
        print(f"Saved to: {os.path.abspath(local_path)}")
        print_stats(received, start, "Download")

    def delete(self, remote_name):
        try:
            remote_name = sanitize_filename(remote_name)
        except ClientError as exc:
            raise ClientError(str(exc)) from None
        self.send_line(f"DELETE {remote_name}")
        reply = self.recv_line()
        self.expect_ok(reply)
        print(f"[server] {reply}")

    # ---- interactive shell ----------------------------------------------

    def repl(self):
        print("Interactive file client. Type 'help' for commands.\n")
        while True:
            try:
                text = input("file-client> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nbye")
                return
            if not text:
                continue

            command, _, arg = text.partition(" ")
            command = command.lower()

            try:
                if command in ("quit", "exit"):
                    return
                elif command == "help":
                    print(HELP_TEXT)
                elif command == "list":
                    names = self.list_files()
                    if not names:
                        print("(no files on the server)")
                    for name in names:
                        print(f"  {name}")
                    print(f"{len(names)} file(s)")
                elif command == "upload":
                    parts = shlex.split(arg)
                    if not parts:
                        print("usage: upload <local-file> [remote-name]")
                        continue
                    local = parts[0]
                    remote = parts[1] if len(parts) > 1 else None
                    self.upload(local, remote)
                elif command == "download":
                    parts = shlex.split(arg)
                    if not parts:
                        print("usage: download <remote-file> [save-as-or-dir]")
                        continue
                    remote = parts[0]
                    target = parts[1] if len(parts) > 1 else None
                    self.download(remote, target)
                elif command == "delete":
                    parts = shlex.split(arg)
                    if not parts:
                        print("usage: delete <remote-file>")
                        continue
                    self.delete(parts[0])
                else:
                    print(f"Unknown command: {command}  (try 'help')")
            except (ServerError, ClientError, OSError) as exc:
                print(f"error: {exc}")


HELP_TEXT = """\
Commands:
  list                    Show files on the server
  upload <local> [name]   Send a local file (optionally rename it)
  download <remote> [dst] Receive a file (dst = directory or file name)
  delete <remote>         Delete a file on the server (if enabled)
  quit / exit             Disconnect and leave
"""


def main():
    config = load_config()
    if not config["auth_token"]:
        print("config.json has no auth_token; set one to match the server.")
        return

    host = config["host"]
    if host in ("0.0.0.0", ""):                  # don't dial a wildcard bind address
        host = "127.0.0.1"
    port = config["port"]

    print(f"Connecting to {host}:{port} ...")
    client = FileClient(host, port, config["auth_token"], config)
    try:
        client.connect()
        client.repl()
    except ServerError as exc:
        print(f"error: {exc}")
    except (ConnectionRefusedError, socket.timeout, OSError) as exc:
        print(f"error: could not connect to {host}:{port} ({exc})")
    finally:
        client.close()


if __name__ == "__main__":
    main()
