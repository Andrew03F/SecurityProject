import socket

def main():
    HOST = '127.0.0.1'
    PORT = 8080
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print("Server listening on port", PORT)
    conn, addr = server_socket.accept()
    print('Connected to', addr)
    
    while True:
        data = conn.recv(1024)
        if not data:
            break
        print("Received message:", data.decode())
        reply = input("Enter your reply: ")
        conn.sendall(reply.encode())
    
    conn.close()

if __name__ == "__main__":
    main()
