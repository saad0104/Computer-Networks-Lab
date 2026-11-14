import json
import os
import re
import socket
from urllib.parse import quote, unquote

SERVER_HOST = '0.0.0.0'   # listen on all interfaces so other devices can connect
SERVER_PORT =  8080
UPLOAD_DIR  = 'uploads'   # files uploaded from the client are stored here
MAX_UPLOAD  = 20 * 1024 * 1024   # 20 MB limit per upload


def get_local_ip():
    # Find the IP address other devices on the same network can use to reach us.
    # We "connect" a UDP socket to a public address. UDP is connectionless, so no
    # packet is actually sent - the OS just picks the interface it would use for
    # outgoing traffic, and that interface's address is the reachable one.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(('8.8.8.8', 80))
            return probe.getsockname()[0]
    except OSError:
        pass

    # Fallback: resolve the machine's own hostname
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return '127.0.0.1'


def start_server():
    # Create the upload folder once, so uploads have somewhere to go
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # Create a TCP server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Allow immediate reuse of the port after the server restarts
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to server address and port
    server_socket.bind((SERVER_HOST, SERVER_PORT))

    # Listen for incoming connections (backlog = 5 pending connections)
    server_socket.listen(5)

    print(f"Server is running and listening on port {SERVER_PORT} ...")
    print("Waiting for a browser request from a client PC...\n")

    # Show the addresses so the page is easy to open from another device
    local_ip = get_local_ip()
    print("Open this page in a browser:")
    print(f"  On this PC     : http://127.0.0.1:{SERVER_PORT}/index.html")
    print(f"  From another PC: http://{local_ip}:{SERVER_PORT}/index.html")
    print("  (client and server must be on the same Wi-Fi / LAN)\n")

    while True:
        # Accept a new connection -> creates a new socket for this client
        connection_socket, client_address = server_socket.accept()
        print(f"Connection received from {client_address}")

        try:
            handle_request(connection_socket)
        except Exception as e:
            print(f"Error handling request: {e}")
        finally:
            connection_socket.close()


def handle_request(connection_socket):
    request_line, headers, body = receive_request(connection_socket)

    if not request_line:
        return

    print("---- Request received ----")
    print(request_line)

    parts = request_line.split()
    if len(parts) < 2:
        send_error_response(connection_socket, 400, "Bad Request")
        return

    method, target = parts[0], parts[1]

    if method == 'GET':
        handle_get(connection_socket, target)
    elif method == 'POST':
        handle_upload(connection_socket, headers, body)
    else:
        send_error_response(connection_socket, 405, "Method Not Allowed")


def receive_request(connection_socket):
    # Read until the end of the HTTP headers (\r\n\r\n).
    # A single recv() is not guaranteed to return the whole request.
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = connection_socket.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 65536:   # headers should never be this big
            break

    head, _, body = data.partition(b'\r\n\r\n')
    lines = head.decode('utf-8', errors='replace').split('\r\n')
    request_line = lines[0] if lines else ''

    # Parse the headers into a lowercase dictionary: {'content-length': '123', ...}
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip().lower()] = value.strip()

    try:
        content_length = int(headers.get('content-length', 0))
    except ValueError:
        content_length = 0

    # Refuse oversized uploads before reading the body into memory
    if content_length > MAX_UPLOAD:
        send_error_response(connection_socket, 413, "Payload Too Large")
        return None, {}, b''

    # curl and some clients wait for this before sending a large body
    if headers.get('expect', '').lower() == '100-continue':
        connection_socket.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

    # The body usually arrives in later packets, so keep reading until we
    # have exactly Content-Length bytes.
    while len(body) < content_length:
        chunk = connection_socket.recv(65536)
        if not chunk:
            break
        body += chunk

    return request_line, headers, body


def handle_get(connection_socket, target):
    # Remove the query string (e.g. /index.html?uploaded=notes.txt)
    # and decode percent-escapes (e.g. %20 -> space).
    filename = unquote(target.split('?')[0].lstrip('/'))

    # No file name -> serve the home page
    if filename == '':
        filename = "index.html"

    # Small JSON endpoint so the page can list the uploaded files
    if filename == 'uploads.json':
        send_upload_list(connection_socket)
        return

    # Security: keep every request inside the server's own folder.
    # Without this, a request like GET /../secret.txt could escape it.
    base_dir = os.path.abspath('.')
    file_path = os.path.abspath(filename)
    if file_path != base_dir and not file_path.startswith(base_dir + os.sep):
        send_error_response(connection_socket, 403, "Forbidden")
        print(f"Blocked path traversal attempt: {filename}\n")
        return

    # Try to obtain the requested file from the server's file system
    try:
        with open(file_path, 'rb') as f:
            file_content = f.read()
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        send_error_response(connection_socket, 404, "Not Found")
        print(f"Response: HTTP/1.1 404 Not Found")
        print(f"File '{filename}' not found on server.\n")
        return

    # For text files: convert lowercase letters to UPPERCASE before sending.
    if filename.endswith('.txt'):
        file_content = file_content.upper()
        print(f"Converted '{filename}' to uppercase")

    # Create the HTTP response message (status line + headers + blank line + file)
    content_type = get_content_type(filename)
    header = (
        "HTTP/1.1 200 OK\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(file_content)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )

    # Send response to client (header first, then file bytes)
    # sendall() keeps going until every byte is sent (send() can stop early on big files)
    connection_socket.sendall(header.encode())
    connection_socket.sendall(file_content)
    print("Response: HTTP/1.1 200 OK")
    print(f"Sent '{filename}' successfully ({len(file_content)} bytes)\n")


def handle_upload(connection_socket, headers, body):
    content_type = headers.get('content-type', '')

    if not content_type.startswith('multipart/form-data'):
        send_error_response(connection_socket, 400, "Bad Request")
        return

    # Pull the file name and its bytes out of the multipart form data
    file_info = parse_multipart_file(body, content_type)
    if file_info is None:
        send_error_response(connection_socket, 400, "Bad Request")
        return

    filename, content = file_info

    # Never trust a path from the client: keep only the last part of the name.
    # This blocks names like "../../etc/passwd".
    filename = os.path.basename(filename.replace('\\', '/')).strip()
    if filename == '':
        filename = 'upload.bin'

    save_path = os.path.join(UPLOAD_DIR, filename)
    with open(save_path, 'wb') as f:
        f.write(content)

    print(f"Uploaded '{filename}' ({len(content)} bytes) -> saved to {save_path}\n")

    # Redirect back to the page so the browser shows the refreshed file list
    header = (
        "HTTP/1.1 303 See Other\r\n"
        f"Location: /index.html?uploaded={quote(filename, safe='')}\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    connection_socket.sendall(header.encode())


def parse_multipart_file(body, content_type):
    # The boundary tells us where one form field ends and the next one begins:
    #   ------WebKitFormBoundaryABC123
    match = re.search(r'boundary="?([^";]+)"?', content_type)
    if not match:
        return None

    boundary = b'--' + match.group(1).encode()

    for part in body.split(boundary):
        # Skip the empty pieces between boundaries and the closing boundary
        if part in (b'', b'--', b'--\r\n', b'\r\n'):
            continue
        if part.startswith(b'--'):
            break

        part = part[2:] if part.startswith(b'\r\n') else part

        # Headers of this part, then a blank line, then the raw file bytes
        head, separator, content = part.partition(b'\r\n\r\n')
        if not separator:
            continue

        # Each part ends with the CRLF that belongs to the next boundary
        if content.endswith(b'\r\n'):
            content = content[:-2]

        filename_match = re.search(rb'filename="([^"]*)"', head)
        if filename_match and filename_match.group(1):
            filename = filename_match.group(1).decode('utf-8', errors='replace')
            return filename, content

    return None


def send_upload_list(connection_socket):
    # Build a JSON list of everything currently in the uploads folder
    files = []
    if os.path.isdir(UPLOAD_DIR):
        for name in sorted(os.listdir(UPLOAD_DIR)):
            path = os.path.join(UPLOAD_DIR, name)
            if os.path.isfile(path):
                files.append({"name": name, "size": os.path.getsize(path)})

    body = json.dumps(files).encode()
    header = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    connection_socket.sendall(header.encode())
    connection_socket.sendall(body)
    print(f"Response: HTTP/1.1 200 OK -> sent upload list ({len(files)} files)\n")


def send_error_response(connection_socket, code, message):
    body = f"<html><body><h1>{code} {message}</h1></body></html>"
    header = (
        f"HTTP/1.1 {code} {message}\r\n"
        "Content-Type: text/html\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    connection_socket.sendall(header.encode())
    connection_socket.sendall(body.encode())

def get_content_type(filename):

    # Content-type detection based on file extension
    if filename.endswith('.html') or filename.endswith('.htm'):
        return 'text/html'
    elif filename.endswith('.txt'):
        return 'text/plain; charset=utf-8'
    elif filename.endswith('.jpg') or filename.endswith('.jpeg'):
        return 'image/jpeg'
    elif filename.endswith('.png'):
        return 'image/png'
    elif filename.endswith('.gif'):
        return 'image/gif'
    elif filename.endswith('.svg'):
        return 'image/svg+xml'
    elif filename.endswith('.pdf'):
        return 'application/pdf'
    elif filename.endswith('.css'):
        return 'text/css'
    elif filename.endswith('.js'):
        return 'application/javascript'
    elif filename.endswith('.json'):
        return 'application/json'
    elif filename.endswith('.ppt'):
        return 'application/vnd.ms-powerpoint'
    else:
        return 'application/octet-stream'  # generic binary file

if __name__ == '__main__':
    start_server()
