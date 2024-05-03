import socket

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Get the local machine name
host = socket.gethostname()
port = 12345  # Port to listen on

# Bind to the port
server_socket.bind((host, port))

# Listen for incoming connections
server_socket.listen(5)

print(f"Server listening on {host}:{port}")

while True:
    # Wait for a connection
    client_socket, addr = server_socket.accept()

    print(f"Connection from {addr} has been established.")

    # Send some data to the client
    client_socket.send("Thank you for connecting".encode())

    # Close the connection with the client
    client_socket.close()
