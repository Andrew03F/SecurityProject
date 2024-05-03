import socket

def main():
    HOST = '127.0.0.1'
    PORT = 8080
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
    
    while True:
        message = input("Enter your message: ")
        if message.lower() == 'quit':
            break
        client_socket.sendall(message.encode())
        data = client_socket.recv(1024)
        print("Received reply:", data.decode())
    
    client_socket.close()

if __name__ == "__main__":
    main()
