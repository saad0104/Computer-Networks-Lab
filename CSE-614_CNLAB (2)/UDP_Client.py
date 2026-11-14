import socket
import sys

BUFFER_SIZE = 1024
TIMEOUT_SECONDS = 5   # how long to wait before giving up (UDP has no guaranteed delivery)


def request_file(server_ip, server_port, filename, save_as=None):
    if save_as is None:
        save_as = "received_" + filename

    # Step 1: Create a UDP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(TIMEOUT_SECONDS)

    # Bigger receive buffer - a large file arrives as thousands of datagrams
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)

    server_address = (server_ip, server_port)

    try:
        # Step 2: Send the request "GET <filename>" to the server
        request = f"GET {filename}"
        client_socket.sendto(request.encode(), server_address)
        print(f"Request sent: {request}")

        # Step 3: Wait for the server's initial response (OK/ERR)
        response, _ = client_socket.recvfrom(BUFFER_SIZE)
        response_text = response.decode()

        if response_text.startswith("ERR"):
            print(f"Server error: {response_text}")
            return

        if not response_text.startswith("OK"):
            print(f"Unexpected response: {response_text}")
            return

        filesize = int(response_text.split()[1])
        print(f"Server has the file. Size: {filesize} bytes. Receiving...")

        # Step 4: Receive file content chunks until we see the "END" marker
        # Collect chunks in a list and join once at the end (much faster than += on bytes)
        chunks = []
        while True:
            chunk, _ = client_socket.recvfrom(BUFFER_SIZE)
            if chunk == b"END":
                break
            chunks.append(chunk)
        received_data = b"".join(chunks)

        # Step 5: Save the received file to disk
        with open(save_as, 'wb') as f:
            f.write(received_data)

        print(f"File received successfully and saved as '{save_as}' ({len(received_data)} bytes)")

        # For text files, also show the content here (a UDP client is not a browser,
        # so the terminal is where we see the result)
        if filename.endswith('.txt'):
            print("\n----- File content -----")
            print(received_data.decode('utf-8', errors='replace'))
            print("------------------------")

    except socket.timeout:
        print("Request timed out - no response from server (check IP/port/firewall).")
    finally:
        client_socket.close()


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: python3 udp_client.py <server_ip> <filename> [save_as]")
        sys.exit(1)

    server_ip = sys.argv[1]
    filename = sys.argv[2]
    save_as = sys.argv[3] if len(sys.argv) > 3 else None

    SERVER_PORT = 7000  # must match the port used in udp_server.py

    request_file(server_ip, SERVER_PORT, filename, save_as)