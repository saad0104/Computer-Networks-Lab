#!/usr/bin/env bash
# Automated demo for the teacher: TCP first, then UDP, end to end.
# Shows: server startup, auth, list, upload, list again, download, integrity check.
set -euo pipefail
cd "$(dirname "$0")"

TMP=$(mktemp -d)
cleanup() {
    pkill -f "python3 server.py"     2>/dev/null || true
    pkill -f "python3 udp_server.py" 2>/dev/null || true
    rm -f shared_files/sample.bin shared_files/sample.bin.part-*
    rm -rf "$TMP"
}
trap cleanup EXIT

wait_listen() {   # $1 = server log file
    for _ in $(seq 1 10); do
        grep -qi "listening" "$1" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

# 50 KB of random data so you can watch multi-chunk transfers
head -c 50000 /dev/urandom > "$TMP/sample.bin"
echo "Demo file: 50 KB of random bytes -> $TMP/sample.bin"

echo
echo "=========================== PART 1: TCP ==========================="
python3 server.py > "$TMP/tcp_server.log" 2>&1 &
TCP_PID=$!
wait_listen "$TMP/tcp_server.log"
printf 'help\nlist\nupload %s\nlist\ndownload sample.bin %s\nquit\n' \
    "$TMP/sample.bin" "$TMP/tcp_dl/" | python3 client.py
cmp "$TMP/sample.bin" "$TMP/tcp_dl/sample.bin" && \
    echo ">> TCP round-trip verified: bytes are identical"
kill "$TCP_PID" 2>/dev/null || true
sleep 0.5

echo
echo "=========================== PART 2: UDP ==========================="
python3 udp_server.py > "$TMP/udp_server.log" 2>&1 &
UDP_PID=$!
wait_listen "$TMP/udp_server.log"
printf 'help\nlist\nupload %s\nlist\ndownload sample.bin %s\nquit\n' \
    "$TMP/sample.bin" "$TMP/udp_dl/" | python3 udp_client.py
cmp "$TMP/sample.bin" "$TMP/udp_dl/sample.bin" && \
    echo ">> UDP round-trip verified: bytes are identical"
kill "$UDP_PID" 2>/dev/null || true

echo
echo "============================== DONE ==============================="
echo "Both variants ran the same commands and round-tripped the same file."
