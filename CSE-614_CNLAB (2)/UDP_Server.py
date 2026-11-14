import socket
import time

SERVER_HOST = '0.0.0.0'   # listen on all available interfaces
SERVER_PORT = 7000        # UDP port (pick any free port)
BUFFER_SIZE = 1024        # max size of one UDP datagram we send/receive
CHUNK_SIZE  = 1000        # file data bytes per datagram (leave room for headers)
SEND_DELAY  = 0.0005      # tiny pause between datagrams so a big file doesn't flood the receiver


def start_server():
    # Step 1: Create a UDP socket
    # AF_INET     -> IPv4
    # SOCK_DGRAM  -> UDP (connectionless, no reliability guarantee)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bigger send buffer - helps when sending thousands of datagrams for a large file
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)

    # Step 2: Bind the socket to an address and port
    server_socket.bind((SERVER_HOST, SERVER_PORT))

    print(f"UDP server is running and listening on port {SERVER_PORT} ...")
    print("Waiting for a client request...\n")

    while True:
        # Step 3: Wait for a datagram (blocks until one arrives)
        # No accept()/listen() needed - UDP has no connections
        message, client_address = server_socket.recvfrom(BUFFER_SIZE)
        request = message.decode().strip()
        print(f"Request from {client_address}: {request}")

        handle_request(server_socket, request, client_address)


def handle_request(server_socket, request, client_address):
    # Step 4: Parse the request - expects "GET <filename>"
    parts = request.split()
    if len(parts) != 2 or parts[0] != 'GET':
        server_socket.sendto("ERR Invalid request format".encode(), client_address)
        return

    filename = parts[1].lstrip('/')

    # Step 5: Try to obtain the requested file from the server's file system
    try:
        with open(filename, 'rb') as f:
            file_content = f.read()
    except FileNotFoundError:
        server_socket.sendto(f"ERR File '{filename}' not found".encode(), client_address)
        print(f"File '{filename}' not found.\n")
        return

    # For text files: convert lowercase letters to UPPERCASE before sending.
    # bytes.upper() only changes a-z, so digits, symbols and non-English
    # characters (e.g. Bangla) pass through untouched. The length stays the same.
    if filename.endswith('.txt'):
        file_content = file_content.upper()
        print(f"Converted '{filename}' to uppercase")

    # Step 6: Send an "OK" response with the file size first
    filesize = len(file_content)
    server_socket.sendto(f"OK {filesize}".encode(), client_address)

    # Step 7: Send the file content in fixed-size chunks (datagrams)
    total_sent = 0
    while total_sent < filesize:
        chunk = file_content[total_sent: total_sent + CHUNK_SIZE]
        server_socket.sendto(chunk, client_address)
        total_sent += len(chunk)
        time.sleep(SEND_DELAY)   # pace the datagrams (UDP has no flow control)

    # Step 8: Send an "END" marker so the client knows the transfer is complete
    server_socket.sendto("END".encode(), client_address)
    print(f"Sent '{filename}' successfully ({filesize} bytes) to {client_address}\n")


if __name__ == '__main__':
    start_server()