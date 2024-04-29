import socket

# Define the server's IP and port
SERVER_IP = "127.0.0.1"  # Replace with the actual IP address
SERVER_PORT = 12345

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_socket.bind((SERVER_IP, SERVER_PORT))

# Listen for incoming connections
server_socket.listen(1)

print("Server is listening for incoming connections...")

# Accept a client connection
client_socket, client_address = server_socket.accept()
print("Connection established with:", client_address)

while True:
    # Receive data from the client
    data = client_socket.recv(1024).decode()
    if not data:
        break  # Break the loop if no data received

    print("Received from client:", data)

    # Send a response back to the client
    response = input("Enter a message to send to the client: ")
    client_socket.send(response.encode())

# Close the connection
client_socket.close()
server_socket.close()
