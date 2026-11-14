#!/usr/bin/env python3
"""Interactive client for the UDP file server.

Speaks the same command set as the TCP client but over ``SOCK_DGRAM``.
Because UDP delivers best-effort, unordered datagrams, every exchange is
made reliable here by:

* tagging each request with a random ``req_id`` and ignoring replies that
  do not match it,
* stop-and-wait: after sending a request the client waits for a reply
  (``REP`` or ``ACK``); on timeout it retransmits the same request, up to
  ``udp_max_retries`` times.

File data travels in small datagrams (``udp_payload_size`` bytes each) so
they stay under the Ethernet MTU and avoid IP fragmentation.
"""

import json
import os
import random
import shlex
import socket
import sys
import time

LINE_TERMINATOR = b"\r\n"
RECV_BUF = 65535


class ServerError(Exception):
    """Server replied with an error status code (>= 400)."""


class ClientError(Exception):
    """Local client-side problem (bad file name, missing file, ...)."""


class ProtocolError(Exception):
    """A datagram did not follow the header format."""


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------
def load_config(path="config.json"):
    defaults = {
        "host": "127.0.0.1",
        "port": 8000,
        "auth_token": "",
        "max_upload_size": 100 * 1024 * 1024,
        "udp_payload_size": 1100,
        "udp_timeout_seconds": 1.0,
        "udp_max_retries": 5,
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
    name = name.strip().replace("\\", "/")
    name = os.path.basename(name)
    if not name or name in (".", ".."):
        raise ClientError("invalid file name")
    if "/" in name or "\x00" in name:
        raise ClientError("file name may not contain path separators")
    return name


def make_datagram(req_id, mtype, seq, total, text, payload=b""):
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


def format_size(num):
    for unit in ("B", "KB", "MB", "GB"):
        if num < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} TB"


def print_progress(done, total, start_time, action):
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
class UdpClient:
    """Owns a UDP socket and speaks the request/reply + ACK protocol."""

    def __init__(self, host, port, token, config):
        self.host = host
        self.port = port
        self.token = token
        self.config = config
        self.server = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(config["udp_timeout_seconds"])

    def request(self, text, seq=0, total=1, payload=b"", want_ack=False):
        """Send one REQ and wait for the matching REP (or ACK).

        Retransmits the identical request on timeout; the server answers
        retransmits from its cache, so this is safe to repeat.
        """
        req_id = random.randrange(1, 2 ** 31)
        msg = make_datagram(req_id, "REQ", seq, total, text, payload)
        for attempt in range(self.config["udp_max_retries"] + 1):
            self.sock.sendto(msg, self.server)
            while True:
                try:
                    data, addr = self.sock.recvfrom(RECV_BUF)
                except socket.timeout:
                    break
                if addr != self.server:
                    continue
                try:
                    got_id, mtype, got_seq, got_total, rtext, rpayload = parse_datagram(data)
                except ProtocolError:
                    continue
                if got_id != req_id or got_seq != seq:
                    continue
                if want_ack and mtype == "ACK":
                    return got_id, mtype, got_seq, got_total, rtext, rpayload
                if not want_ack and mtype == "REP":
                    return got_id, mtype, got_seq, got_total, rtext, rpayload
        raise ServerError("no response from server after retries")

    def expect_ok(self, reply):
        code = int(reply[4].split(" ", 1)[0])
        if code >= 400:
            raise ServerError(reply[4])

    # ---- connection lifecycle -------------------------------------------

    def connect(self):
        print(f"Connecting to {self.host}:{self.port} (UDP) ...")
        reply = self.request(f"AUTH {self.token}")
        self.expect_ok(reply)
        print(f"[server] {reply[4]}")

    def close(self):
        try:
            self.request("QUIT")
        except (OSError, ServerError):
            pass
        self.sock.close()

    # ---- commands --------------------------------------------------------

    def list_files(self):
        reply = self.request("LIST")
        self.expect_ok(reply)
        count = int(reply[4].split(" ", 1)[1])
        raw = reply[5].decode("utf-8", errors="replace")
        names = raw.split("\n") if raw else []
        if names and names[-1] == "":
            names.pop()
        return names

    def upload(self, local_path, remote_name=None):
        local_path = os.path.expanduser(local_path)
        if not os.path.isfile(local_path):
            raise ClientError(f"local file not found: {local_path}")

        size = os.path.getsize(local_path)
        remote_name = remote_name or os.path.basename(local_path)
        remote_name = sanitize_filename(remote_name)

        if size > self.config["max_upload_size"]:
            raise ClientError(
                f"file is {format_size(size)} but the local limit is "
                f"{format_size(self.config['max_upload_size'])}"
            )

        tid = random.randrange(1, 2 ** 31)
        reply = self.request(f"UPLOAD {size} {remote_name} {tid}")
        self.expect_ok(reply)

        payload_size = self.config["udp_payload_size"]
        total = (size + payload_size - 1) // payload_size
        start = time.time()
        sent = 0
        with open(local_path, "rb") as fh:
            for i in range(total):
                chunk = fh.read(payload_size)
                self.request(f"DATA {tid}", seq=i, total=total,
                             payload=chunk, want_ack=True)
                sent += len(chunk)
                print_progress(sent, size, start, "uploading")
        print()
        reply = self.request(f"DONE {tid}")
        self.expect_ok(reply)
        print(f"[server] {reply[4]}")
        print_stats(sent, start, "Upload")

    def download(self, remote_name, local_target=None):
        remote_name = sanitize_filename(remote_name)

        reply = self.request(f"DOWNLOAD {remote_name}")
        self.expect_ok(reply)
        size = int(reply[4].split(" ", 1)[1])

        if local_target is None:
            local_target = "."
        local_target = os.path.expanduser(local_target)
        if os.path.isdir(local_target) or local_target.endswith(os.sep):
            local_path = os.path.join(local_target, remote_name)
        else:
            local_path = local_target
        os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)

        payload_size = self.config["udp_payload_size"]
        total = (size + payload_size - 1) // payload_size
        start = time.time()
        received = 0
        with open(local_path, "wb") as fh:
            for i in range(total):
                reply = self.request(f"GET {remote_name} {i}", seq=i, total=total)
                self.expect_ok(reply)
                if reply[2] != i or reply[3] != total:
                    raise ServerError("server sent a mismatched chunk")
                chunk = reply[5]
                fh.write(chunk)
                received += len(chunk)
                print_progress(received, size, start, "downloading")
        print()
        print(f"Saved to: {os.path.abspath(local_path)}")
        print_stats(received, start, "Download")

    def delete(self, remote_name):
        remote_name = sanitize_filename(remote_name)
        reply = self.request(f"DELETE {remote_name}")
        self.expect_ok(reply)
        print(f"[server] {reply[4]}")

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
    if host in ("0.0.0.0", ""):
        host = "127.0.0.1"
    port = config["port"]

    client = UdpClient(host, port, config["auth_token"], config)
    try:
        client.connect()
        client.repl()
    except ServerError as exc:
        print(f"error: {exc}")
    except OSError as exc:
        print(f"error: could not reach {host}:{port} ({exc})")
    finally:
        client.close()


if __name__ == "__main__":
    main()
