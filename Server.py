
import socket
import hashlib

SERVICE_IP = "10.0.0.123"
SERVICE_PORT = 8888

def handle_client(sock):
    while True:
        data, addr = sock.recvfrom(65535)  # Large buffer to handle big packets
        print(f"Received {len(data)} bytes from {addr}")
        
        # Create a SHA-256 digest of the received data
        digest = hashlib.sha256(data).hexdigest()
        
        # Send back the digest as a response
        sock.sendto(digest.encode('utf-8'), addr)

if __name__ == "__main__":
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((SERVICE_IP, SERVICE_PORT))
    print(f"Server listening on {SERVICE_IP}:{SERVICE_PORT}")
    
    handle_client(server_sock)